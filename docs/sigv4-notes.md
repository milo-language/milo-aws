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

## Testing without an AWS account

The published test vectors are the gate — no credentials needed. MinIO can serve
a real S3 endpoint locally for the client half. Do not write tests that require
live AWS: they cannot run in CI and they rot.
