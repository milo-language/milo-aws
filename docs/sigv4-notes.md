# SigV4 notes

Proven before writing the package, the same way SCRAM was proven for the
postgres client: verify the derivation against an independent implementation
first, so a later mismatch is a bug in the client and not in the primitives.

## It works today, byte-exact

`docs/sigv4-probe.milo` computes AWS's documented **get-vanilla** vector in safe
Milo. `scripts/sigv4-oracle.py` computes the same thing with Python's `hmac` and
`hashlib`. They agree, and both match AWS's published signature:

    canonical_sha: bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63
    signature:     5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31

Run both:

    milo run docs/sigv4-probe.milo
    python3 scripts/sigv4-oracle.py

## The derivation chain, and the classic way to break it

    kDate    = HMAC("AWS4" + secret, date)
    kRegion  = HMAC(kDate,   region)
    kService = HMAC(kRegion, service)
    kSigning = HMAC(kService,"aws4_request")
    signature= HMAC(kSigning, stringToSign)          -> hex

Every intermediate keys the next HMAC with the **raw digest**. Hexing an
intermediate is the classic SigV4 bug: it still produces a plausible 64-char
signature, and AWS just answers `SignatureDoesNotMatch` with no indication which
step drifted. `std/hmac` gives both forms — `Hmac.sha256Bytes` (raw) for the
chain, `Hmac.sha256` (hex) for the final step only.

## What the package still has to get right

The probe does the cryptography. The parts that actually break real clients are
the *canonicalisation* rules, none of which the probe exercises:

* **Query strings** sorted by name then value, each component URI-encoded, with
  `=` for empty values.
* **Headers** lowercased, values trimmed of leading/trailing space with internal
  runs collapsed, sorted by name, and `SignedHeaders` listing exactly what was
  signed.
* **Path** URI-encoded — but S3 does **not** double-encode the path, while every
  other service does. This is the single most common source of
  `SignatureDoesNotMatch` against S3.
* **Payload hash** as `x-amz-content-sha256`; `UNSIGNED-PAYLOAD` is allowed for
  S3 over HTTPS and is what makes streaming a large body possible without
  buffering it to hash first.
* **Presigned URLs** move the credential into the query string and require
  `X-Amz-Expires`; the signature covers the query, not a header.

## Where all of this ended up

The list above is now implemented in `lib.milo` and pinned by
`tests/sigv4_test.milo`. Two things are worth knowing before changing any of it:

* **The path-encoding rule is a constructor, not an inference.** `Request.forS3`
  encodes once, `Request.new` encodes twice. Nothing derives it from the service
  string passed to `sign` — a wrong answer there should look like a choice
  somebody made, not an accident.
* **The expected signatures in the suite are not hand-written.**
  `scripts/sigv4-oracle.py` grew from the get-vanilla check into a full
  independent implementation and prints one signature per case;
  `scripts/run-tests.sh` greps every one of them out of the test file. If the two
  ever drift, the gate fails rather than the suite quietly asserting constants
  nothing produces any more.

One bug found on the way, in the compiler's own stdlib rather than here:
`std/fetch` built its `Host` header without the port, so every request to a
non-default port sent `Host: 127.0.0.1` for a connection to `127.0.0.1:59000`.
RFC 7230 §5.4 requires the port, and SigV4 signs the header verbatim — so a
signature made over the correct authority is rejected by the server that received
the wrong one. Fixed upstream with `hostHeader()`.

## Testing without an AWS account

The published test vectors are the gate — no credentials needed. MinIO can serve
a real S3 endpoint locally for the client half. Do not write tests that require
live AWS: they cannot run in CI and they rot.
