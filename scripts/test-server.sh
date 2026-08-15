#!/bin/sh
# Stand up a throwaway MinIO as a real S3 endpoint, and tear it down.
#
# MinIO speaks the S3 API and verifies SigV4 for real, which is the point: a
# hand-rolled fake would accept whatever signature the client produced and the
# tests would prove nothing about signing. It also needs no AWS account, so this
# runs in CI and on a laptop identically.
set -e
DIR="${MILO_S3_DIR:-/tmp/milo-s3-test}"
PORT="${MILO_S3_PORT:-59000}"
KEY="${MILO_S3_KEY:-miniotestkey}"
SECRET="${MILO_S3_SECRET:-miniotestsecret}"

case "$1" in
  start)
    rm -rf "$DIR"; mkdir -p "$DIR/data"
    MINIO_ROOT_USER="$KEY" MINIO_ROOT_PASSWORD="$SECRET" \
      minio server "$DIR/data" --address "127.0.0.1:$PORT" \
      > "$DIR/log" 2>&1 &
    echo $! > "$DIR/pid"
    # Readiness, checked rather than slept: MinIO's liveness probe answers 200
    # once the object layer is up. A fixed sleep raced on a loaded machine, and a
    # loop with no check is the silent-success trap — it would "succeed" with a
    # dead server and every test would then fail for the wrong reason.
    ok=""
    i=0
    while [ $i -lt 100 ]; do
      if curl -fsS "http://127.0.0.1:$PORT/minio/health/live" >/dev/null 2>&1; then ok=1; break; fi
      sleep 0.1
      i=$((i+1))
    done
    if [ -z "$ok" ]; then
      echo "minio failed to become ready; log follows" >&2
      cat "$DIR/log" >&2
      exit 1
    fi
    echo "s3://$KEY:$SECRET@127.0.0.1:$PORT"
    ;;
  stop)
    [ -f "$DIR/pid" ] && kill "$(cat "$DIR/pid")" 2>/dev/null || true
    [ -f "$DIR/pid" ] && while kill -0 "$(cat "$DIR/pid")" 2>/dev/null; do sleep 0.1; done
    rm -rf "$DIR"
    ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
