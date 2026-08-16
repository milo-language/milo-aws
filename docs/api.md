# aws API

## The signer is the useful half

SigV4 is identical for every AWS service, so `sign` works against DynamoDB, SQS,
Lambda or anything else even though S3 is the only client here.

```milo
from "aws" import { Credentials, Request, sign, amzNow }

var req = Request.new("POST", "https://dynamodb.us-east-1.amazonaws.com/")
req.setHeader("content-type", "application/x-amz-json-1.0")
req.setHeader("x-amz-target", "DynamoDB_20120810.ListTables")
req.setBody("{}")

let signed = sign(req, creds, "us-east-1", "dynamodb", amzNow())
```

`SignedRequest` carries `method`, `url`, `headers` and `body` — everything that
must go on the wire, `Host` included. `sendSigned(signed)` will do it, or hand the parts
to any client that will reproduce the `Host` header verbatim and not follow a
redirect.

**`sign` and `presign` take the timestamp as a parameter.** A signature is a pure
function of its inputs, and that is the only thing that makes it testable against
AWS's published vectors — a signer that reads the clock internally can never
reproduce a fixed one. `amzNow()` is the live answer when you want it.

### Path encoding is an explicit choice

This is the single most common cause of `SignatureDoesNotMatch`, and the failure
tells you nothing about which end is wrong:

**S3 encodes the request path once. Every other AWS service encodes it twice.**

So there are two constructors, and picking one is the whole decision:

```milo
Request.forS3("GET", url)    // single encoding, x-amz-content-sha256 sent and signed
Request.new("GET", url)      // double encoding, no content hash header
```

Nothing here infers it from the service name you pass to `sign` — that would make
a wrong answer look like an accident rather than a choice.

### What gets canonicalised

- **Query** sorted by name then value, both halves percent-encoded, `=` kept for
  an empty value. Put parameters in `req.query` (via `addQuery`) or write them in
  the URL — `Request.new` lifts a `?…` tail into `query` and both spellings sign
  identically.
- **Headers** lowercased, values trimmed with internal whitespace runs collapsed,
  sorted, repeats of one name merged with commas, and `SignedHeaders` listing
  exactly what was signed.
- **Path** percent-encoded per the rule above. `~` stays literal, a space is `%20`
  and never `+`, and hex is uppercase.
- **Payload** hashed into `x-amz-content-sha256`. `req.setUnsignedPayload()`
  substitutes `UNSIGNED-PAYLOAD`, which is legal for S3 over HTTPS and is what
  makes streaming a large body possible without buffering it to hash first — over
  plain HTTP it removes the request's only integrity check.
- **Host** carries the port whenever it is not the scheme's default. RFC 7230 §5.4
  requires it and SigV4 signs the header verbatim, so a portless `Host` against a
  server on port 9000 is a rejected request.

### Presigned URLs

```milo
let url = presign(req, creds, "us-east-1", "s3", 900, amzNow())
```

The credential, the timestamp and `X-Amz-Expires` move into the query string, the
payload becomes `UNSIGNED-PAYLOAD`, and the signature covers the query rather than
an `Authorization` header. Only `host` is signed unless you add headers yourself —
anything signed has to be *sent* by whoever fetches the URL, and a browser will
not send an `x-amz-*` header for you.

## Credentials

`Credentials.resolve()` walks the chain in order:

1. **Explicit** — build a `Credentials` yourself and never call `resolve`.
2. **Environment** — `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
   `AWS_SESSION_TOKEN` when present. Both halves of the pair are required: half a
   pair is a misconfiguration, and quietly falling through to a profile would sign
   with keys nobody chose.
3. **Profile** — the `AWS_PROFILE` section (default `default`) of
   `~/.aws/credentials`, or `AWS_SHARED_CREDENTIALS_FILE`. Sections there are bare
   `[name]`; the `[profile name]` spelling belongs to `~/.aws/config`, which this
   does not read.

A session token is not decoration. When one is present it is sent as
`x-amz-security-token` **and** listed in `SignedHeaders` — doing only the first is
the usual reason temporary credentials "do not work". `sign` does both, so you
cannot forget.

`listObjectsV2` follows continuation tokens to the end, so it returns everything
under the prefix rather than S3's first 1000 keys. `s3.setPageSize(n)` changes the
page size — mainly so the continuation loop is testable against three objects
instead of a thousand.

## Errors

`AwsError` keeps S3's own code:

```milo
match s3.getObject("my-bucket", "gone.txt") {
    Result.Ok(body) => { print(body) }
    Result.Err(e) => {
        if e.isNotFound() { print("not there") }
        print(e.code)       // NoSuchKey
        print(e.status)     // 404
    }
}
```

`code` is stable across regions and releases and is the part to branch on;
`message` is prose and gets reworded. `kind` separates `S3` (the server answered)
from `CLIENT` (nothing reached one) and `CONFIG` (no credentials found).

## Addressing

Path style — `https://host/bucket/key`. That works against AWS, against MinIO, and
against an endpoint given as a bare IP. Virtual-hosted addressing
(`https://bucket.host/key`) is not implemented.

## Not implemented

Deliberately out of scope for v0.1. None of these are stubs that silently do
nothing — they are absent, and a program that needs one fails saying so:

- **IMDSv2 / instance roles**, and **AssumeRole / STS**. `resolve()` reads the
  environment and the credentials file, and reports both paths it checked when it
  finds nothing. An STS session token you obtain some other way works fine.
- **Multipart upload.** `putObject` is one request; the practical ceiling is S3's
  5 GB single-PUT limit, and the body is held in memory.
- **Streaming uploads** (`aws-chunked`, `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`).
  `setUnsignedPayload()` gets you an un-hashed body, but the body is still one
  buffer.
- **Any service other than S3.** The signer is service-agnostic and tested that
  way; there is simply no second client.
- **Retries and backoff.** Every call is one request. A 503 comes back as a 503.
- **Checksums beyond `x-amz-content-sha256`** — no `x-amz-checksum-crc32` etc.
- **Virtual-hosted addressing**, per above.
- **A general XML parser.** The S3 responses this reads are flat elements inside a
  known parent, and that is exactly what it extracts. Nested or attribute-bearing
  XML is out of reach.
- **Quoted-string exemption in header normalisation.** AWS leaves whitespace runs
  alone inside a quoted header value; this collapses them unconditionally. It only
  differs on a header you supply with embedded quotes.

## Tests

The signer tests need no server and are the ones that matter. Every expected
signature comes from `scripts/sigv4-oracle.py` — an independent implementation
written from AWS's spec on Python's `hmac`/`hashlib`, whose `get-vanilla` case is
checked against AWS's own published value before it prints anything. The gate
re-runs the oracle and greps every signature it prints out of the test file, so
the two cannot drift apart silently.

`tests/sigv4_test.milo` and `tests/s3_test.milo` also carry the negative controls: one byte of the secret,
and one character of the canonical request, must each move the signature. Without
them a signer that returned a constant would pass every positive case.

The S3 tests run against **MinIO**, which validates SigV4 for real — a hand-rolled
fake would accept whatever signature the client produced and prove nothing. The
last step reads the objects back with `curl --aws-sigv4`, a second signer, because
a client that mis-signed and mis-verified the same way agrees with itself
perfectly.

```bash
sh scripts/run-tests.sh        # the whole gate: oracle, server up, suite, example, curl, server down
```

or by hand:

```bash
python3 scripts/sigv4-oracle.py
milo test tests/sigv4_test.milo        # no server needed
sh scripts/test-server.sh start
milo test tests/s3_test.milo
AWS_ACCESS_KEY_ID=miniotestkey AWS_SECRET_ACCESS_KEY=miniotestsecret milo run examples/s3.milo
sh scripts/test-server.sh stop
```

`docs/sigv4-notes.md` records the derivation chain and the canonicalisation rules
that actually break clients; `docs/sigv4-probe.milo` is the standalone probe that
proved the crypto composed before any of this was written.
