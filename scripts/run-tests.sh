#!/bin/sh
# The whole gate in one command: oracle, suite, example, an independent
# cross-check with curl, and the server torn down whether or not any of it passed.
#
#   sh scripts/run-tests.sh
#   MILO="bun run ../../milo/src/main.ts" sh scripts/run-tests.sh   # from a checkout
set -e
cd "$(dirname "$0")/.."
MILO="${MILO:-milo}"
PORT="${MILO_S3_PORT:-59000}"
KEY="${MILO_S3_KEY:-miniotestkey}"
SECRET="${MILO_S3_SECRET:-miniotestsecret}"
ENDPOINT="http://127.0.0.1:$PORT"

# EXIT alone is not enough: a ^C mid-run leaves a minio holding the port, and the
# next run then fails to bind for a reason that has nothing to do with the code.
cleanup() {
  sh scripts/test-server.sh stop >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# The signer half needs no server, and it is the half that matters — run it
# first so a signing regression is reported before anything can blame the network.
echo "==> oracle (independent SigV4, checked against AWS's published vector)"
python3 scripts/sigv4-oracle.py | tee /tmp/milo-aws-oracle.txt

# The suite asserts fixed hex signatures. They came from the oracle, and nothing
# stops them going stale — so every signature the oracle just printed has to
# appear in the test file. Drift fails here instead of leaving the suite green
# against constants nothing produces any more.
echo "==> oracle/test cross-check"
sed -n 's/.*signature=\([0-9a-f]*\).*/\1/p' /tmp/milo-aws-oracle.txt | while read -r sig; do
  grep -q "$sig" tests/sigv4_test.milo || { echo "oracle signature $sig is not asserted in tests/sigv4_test.milo"; exit 1; }
done
grep -q "$(sed -n 's/^presigned_url=.*X-Amz-Signature=//p' /tmp/milo-aws-oracle.txt)" tests/sigv4_test.milo \
  || { echo "the oracle's presigned signature is not asserted in tests/sigv4_test.milo"; exit 1; }
echo "    every signature the oracle prints is asserted in the suite"

echo "==> signer tests (no server needed)"
$MILO test tests/sigv4_test.milo

echo "==> starting throwaway MinIO"
sh scripts/test-server.sh start
echo "    $ENDPOINT"

echo "==> s3 tests"
MILO_S3_ENDPOINT="$ENDPOINT" MILO_S3_KEY="$KEY" MILO_S3_SECRET="$SECRET" \
  $MILO test tests/s3_test.milo

echo "==> example"
AWS_ACCESS_KEY_ID="$KEY" AWS_SECRET_ACCESS_KEY="$SECRET" \
  MILO_S3_ENDPOINT="$ENDPOINT" $MILO run examples/s3.milo > /tmp/milo-aws-example.txt
cat /tmp/milo-aws-example.txt

# Everything above is this client agreeing with itself. curl implements SigV4
# independently (--aws-sigv4), so it is a second signer reading the objects the
# example and the suite just wrote. Without this step a client that mis-signed
# and mis-verified in the same way would look perfect.
echo "==> curl cross-check"
s3get() {
  curl -sS --fail --aws-sigv4 "aws:amz:us-east-1:s3" --user "$KEY:$SECRET" "$ENDPOINT/$1"
}

[ "$(s3get milo-aws-example/notes/hello.txt)" = "hello from milo" ] \
  || { echo "curl does not see what the example wrote"; exit 1; }
[ "$(s3get milo-aws-test/roundtrip/hello.txt)" = "hello from milo" ] \
  || { echo "curl does not see what the suite wrote"; exit 1; }

# The binary object, counted by a tool that is not us: 13 bytes with NUL and 0xff
# in the middle. A client that treated the body as C text would have truncated it.
s3get milo-aws-test/roundtrip/binary.bin > /tmp/milo-aws-bin
[ "$(wc -c < /tmp/milo-aws-bin | tr -d ' ')" = "13" ] \
  || { echo "the binary object is not 13 bytes on the server"; exit 1; }
od -An -tx1 /tmp/milo-aws-bin | tr -d ' \n' | grep -q '68656164' \
  || { echo "the binary object lost its head"; exit 1; }
od -An -tx1 /tmp/milo-aws-bin | tr -d ' \n' | grep -q '00ff00' \
  || { echo "the binary object lost its NUL/0xff run"; exit 1; }

# The presigned URL, fetched with no credentials at all. This is what proves the
# URL is a real URL and not merely one our own client accepts.
PRESIGNED="$(sed -n 's/^presigned: //p' /tmp/milo-aws-example.txt)"
[ -n "$PRESIGNED" ] || { echo "the example printed no presigned URL"; exit 1; }
[ "$(curl -sS "$PRESIGNED")" = "hello from milo" ] \
  || { echo "the presigned URL does not fetch"; exit 1; }
# And one character less of a signature must stop working, or the line above
# would pass against a server that ignored the query.
[ "$(curl -sS -o /dev/null -w '%{http_code}' "${PRESIGNED%?}")" = "403" ] \
  || { echo "a tampered presigned URL was accepted"; exit 1; }

echo "    curl agrees: text and 13-byte binary objects, and the presigned URL"
echo "==> all green"
