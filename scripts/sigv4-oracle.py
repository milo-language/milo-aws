#!/usr/bin/env python3
"""An independent SigV4 implementation, used as the oracle for tests/aws_test.milo.

Written from AWS's specification rather than translated from lib.milo, which is
the whole point: if both were the same code in two syntaxes, agreement would
prove nothing. Python supplies hmac/hashlib, so the primitives are independent
too.

It prints one line per case:

    case=<name> canonical_sha=<hex> signature=<hex>

`get-vanilla` is checked here against AWS's published value before anything else
is printed, so a broken oracle fails loudly instead of blessing a broken client.
scripts/run-tests.sh then greps every signature printed here out of
tests/aws_test.milo — if the two ever drift, the gate fails rather than the
suite quietly asserting stale constants.
"""
import hashlib, hmac, string, sys

UNRESERVED = set(string.ascii_letters + string.digits + "-_.~")
ALGO = "AWS4-HMAC-SHA256"
AWS_PUBLISHED_VANILLA = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"


def uri_encode(s, encode_slash=True):
    out = []
    for b in s.encode("utf-8"):
        c = chr(b)
        if c in UNRESERVED:
            out.append(c)
        elif c == "/" and not encode_slash:
            out.append(c)
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def canonical_path(path, double):
    if not path:
        return "/"
    e = uri_encode(path, encode_slash=False)
    if double:
        # Every service except S3 encodes the path a second time. S3 does not,
        # and mixing the two up is the classic S3 SignatureDoesNotMatch.
        e = uri_encode(e, encode_slash=False)
    return e


def canonical_query(pairs):
    enc = [(uri_encode(k), uri_encode(v)) for k, v in pairs]
    enc.sort()  # by name, then value — a plain tuple sort is exactly that rule
    return "&".join(k + "=" + v for k, v in enc)


def canonical_headers(headers):
    """-> (canonical block, signed-header list). Values are trimmed and their
    internal whitespace runs collapsed; same-named headers are merged with a
    comma, in the order given."""
    norm = []
    for name, value in headers:
        norm.append((name.strip().lower(), " ".join(value.split())))
    merged = {}
    order = []
    for name, value in norm:
        if name in merged:
            merged[name] = merged[name] + "," + value
        else:
            merged[name] = value
            order.append(name)
    order.sort()
    block = "".join(n + ":" + merged[n] + "\n" for n in order)
    return block, ";".join(order)


def host_of(url):
    rest = url.split("://", 1)[1]
    authority = rest.split("/", 1)[0]
    scheme = url.split("://", 1)[0]
    if ":" in authority:
        host, port = authority.rsplit(":", 1)
        default = "443" if scheme == "https" else "80"
        return authority if port != default else host
    return authority


def path_of(url):
    rest = url.split("://", 1)[1]
    slash = rest.find("/")
    return "/" if slash < 0 else rest[slash:]


def sign_key(secret, datestamp, region, service):
    def h(k, m):
        return hmac.new(k, m.encode("utf-8"), hashlib.sha256).digest()
    k = h(("AWS4" + secret).encode("utf-8"), datestamp)
    k = h(k, region)
    k = h(k, service)
    return h(k, "aws4_request")


def sigv4(method, url, query, headers, body, ak, sk, token, region, service,
          now, double_encode, content_sha_header, payload_hash=None):
    datestamp = now[:8]
    payload = payload_hash or hashlib.sha256(body.encode("utf-8")).hexdigest()
    hs = [("host", host_of(url)), ("x-amz-date", now)] + list(headers)
    if content_sha_header:
        hs.append(("x-amz-content-sha256", payload))
    if token:
        hs.append(("x-amz-security-token", token))
    chdr, signed = canonical_headers(hs)
    creq = "\n".join([
        method,
        canonical_path(path_of(url), double_encode),
        canonical_query(query),
        chdr,
        signed,
        payload,
    ])
    creq_sha = hashlib.sha256(creq.encode("utf-8")).hexdigest()
    scope = "%s/%s/%s/aws4_request" % (datestamp, region, service)
    sts = "\n".join([ALGO, now, scope, creq_sha])
    sig = hmac.new(sign_key(sk, datestamp, region, service),
                   sts.encode("utf-8"), hashlib.sha256).hexdigest()
    return creq_sha, sig, signed


def presign(method, url, query, ak, sk, token, region, service, now, expires,
            double_encode):
    datestamp = now[:8]
    scope = "%s/%s/%s/aws4_request" % (datestamp, region, service)
    # The credential moves into the query string, and the signature covers the
    # query rather than an Authorization header.
    q = list(query) + [
        ("X-Amz-Algorithm", ALGO),
        ("X-Amz-Credential", ak + "/" + scope),
        ("X-Amz-Date", now),
        ("X-Amz-Expires", str(expires)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    if token:
        q.append(("X-Amz-Security-Token", token))
    cq = canonical_query(q)
    creq = "\n".join([
        method,
        canonical_path(path_of(url), double_encode),
        cq,
        "host:" + host_of(url) + "\n",
        "host",
        "UNSIGNED-PAYLOAD",
    ])
    creq_sha = hashlib.sha256(creq.encode("utf-8")).hexdigest()
    sts = "\n".join([ALGO, now, scope, creq_sha])
    sig = hmac.new(sign_key(sk, datestamp, region, service),
                   sts.encode("utf-8"), hashlib.sha256).hexdigest()
    return creq_sha, sig, url + "?" + cq + "&X-Amz-Signature=" + sig


AK = "AKIDEXAMPLE"
SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
NOW = "20150830T123600Z"
REGION = "us-east-1"


def main():
    out = []

    # 1. AWS's documented get-vanilla vector. Double path encoding, no
    #    x-amz-content-sha256 header: that header is an S3 requirement, and
    #    adding it everywhere would change this signature.
    sha, sig, _ = sigv4("GET", "https://example.amazonaws.com/", [], [], "",
                        AK, SK, None, REGION, "service", NOW,
                        double_encode=True, content_sha_header=False)
    if sig != AWS_PUBLISHED_VANILLA:
        print("oracle disagrees with AWS's published get-vanilla signature:",
              sig, file=sys.stderr)
        return 1
    out.append(("get-vanilla", sha, sig))

    # 2. A query string that is wrong unless it is sorted by name THEN value and
    #    each half encoded: duplicate names out of order, an empty value that
    #    still needs its '=', a space, and slashes that must become %2F.
    q = [("prefix", "a/b"), ("delimiter", "/"), ("marker", "key with spaces"),
         ("a", "2"), ("a", "1"), ("empty", "")]
    sha, sig, _ = sigv4("GET", "https://s3.example.com/bucket", q, [], "",
                        AK, SK, None, REGION, "s3", NOW,
                        double_encode=False, content_sha_header=True)
    out.append(("query-sort", sha, sig))

    # 3. Header values needing trim + internal-run collapse, names needing
    #    lowercasing and reordering.
    h = [("X-Amz-Meta-Note", "  hello   world  "),
         ("Content-Type", "text/plain"),
         ("X-Amz-Meta-Alpha", "one")]
    sha, sig, _ = sigv4("PUT", "https://s3.example.com/bucket/obj", [], h,
                        "hello", AK, SK, None, REGION, "s3", NOW,
                        double_encode=False, content_sha_header=True)
    out.append(("header-collapse", sha, sig))

    # 4. The same literal path under both rules. These two signatures MUST
    #    differ; a client that double-encodes for S3 produces 4b's signature and
    #    gets SignatureDoesNotMatch from S3.
    p = "https://s3.example.com/bucket/docs/a b+c~d.txt"
    sha, sig, _ = sigv4("GET", p, [], [], "", AK, SK, None, REGION, "s3", NOW,
                        double_encode=False, content_sha_header=True)
    out.append(("s3-path-single", sha, sig))
    sha, sig, _ = sigv4("GET", p, [], [], "", AK, SK, None, REGION, "service",
                        NOW, double_encode=True, content_sha_header=False)
    out.append(("path-double", sha, sig))

    # 5. A session token is a signed header, not just a sent one.
    sha, sig, signed = sigv4("GET", "https://s3.example.com/bucket/k", [], [],
                             "", AK, SK, "FQoDYXdzEDMaTOKEN", REGION, "s3",
                             NOW, double_encode=False, content_sha_header=True)
    assert signed == "host;x-amz-content-sha256;x-amz-date;x-amz-security-token", signed
    out.append(("session-token", sha, sig))

    # 6. Presigned GET: credential in the query, X-Amz-Expires required.
    sha, sig, url = presign("GET", "https://s3.example.com/bucket/key.txt", [],
                            AK, SK, None, REGION, "s3", NOW, 900,
                            double_encode=False)
    out.append(("presign", sha, sig))

    # 7. Negative controls. One byte of the secret, and one character of the
    #    canonical request. Both must move the signature — without these a
    #    signer that returned a constant would pass every case above.
    sha, sig, _ = sigv4("GET", "https://example.amazonaws.com/", [], [], "",
                        AK, SK[:-1] + "Z", None, REGION, "service", NOW,
                        double_encode=True, content_sha_header=False)
    assert sig != AWS_PUBLISHED_VANILLA
    out.append(("bad-secret", sha, sig))
    sha, sig, _ = sigv4("GET", "https://example.amazonaws.com/x", [], [], "",
                        AK, SK, None, REGION, "service", NOW,
                        double_encode=True, content_sha_header=False)
    assert sig != AWS_PUBLISHED_VANILLA
    out.append(("bad-path", sha, sig))

    for name, sha, sig in out:
        print("case=%-16s canonical_sha=%s signature=%s" % (name, sha, sig))
    print("presigned_url=" + url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
