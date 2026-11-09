#!/usr/bin/env bash
# The filter's go-ftw tests against a webfast binary, in Docker (ci/ftw/compose.yaml: the binary
# on alpine, albedo as the backend, go-ftw; the images pinned there).
#
#   WEBFAST_BIN=path/to/webfast scripts/ftw-run.sh [all] [cve]     (none named: both)
#
# all: every built-in set, as the filter ships; the tests of ci/ftw/ftw-all.yaml's `ignore` are
#      skipped, each for its reason. cve: the cve set alone, its tests only, nothing ignored.
# Each pass starts a fresh webfast with its filter file and an empty log. The output of go-ftw,
# the filter's log and the server's own log of each pass go to FTW_OUT (default ci/ftw/out).
#
# The binary: webfast built with this checkout's modules, static as webfast's release builds it,
# e.g. in a webfast checkout next to this one
#   RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --release -p webfast \
#     --target x86_64-unknown-linux-musl --features webfast-ngfw/libinjection \
#     --config 'patch."https://github.com/ops-pro/webfast-modules".webfast-ngfw.path="../webfast-modules/crates/webfast-ngfw"' \
#     --config 'patch."https://github.com/ops-pro/webfast-modules".webfast-challenge.path="../webfast-modules/crates/webfast-challenge"'
# (the patch rewrites webfast's Cargo.lock: do not commit it there).
set -uo pipefail

: "${WEBFAST_BIN:?WEBFAST_BIN names the webfast binary to test}"
WEBFAST_BIN=$(realpath "$WEBFAST_BIN") || exit 2
export WEBFAST_BIN
cd "$(dirname "$0")/../ci/ftw" || exit 2
FTW_OUT=$(mkdir -p "${FTW_OUT:-out}" && realpath "${FTW_OUT:-out}") || exit 2
export FTW_OUT

passes=("$@")
[ ${#passes[@]} -gt 0 ] || passes=(all cve)
failed=()
for pass in "${passes[@]}"; do
  case "$pass" in
    all) dir=/tests ;;
    cve) dir=/tests/cve ;;
    *) echo "unknown pass $pass (all, cve)" >&2; exit 2 ;;
  esac
  export FTW_PASS=$pass
  echo "== $pass"
  docker compose down -v --remove-orphans >/dev/null 2>&1
  if ! docker compose up -d --wait webfast albedo; then
    docker compose logs webfast >"$FTW_OUT/webfast-$pass.log" 2>&1
    failed+=("$pass")
    continue
  fi
  # The filter creates its log at its first line, and go-ftw opens it before its first request.
  docker compose exec -T webfast touch /var/log/web/ngfw.log
  docker compose run --rm -T goftw run --config "/ftw-$pass.yaml" -d "$dir" \
    --show-failures-only --read-timeout 5s \
    2>&1 | tee "$FTW_OUT/ftw-$pass.txt"
  [ "${PIPESTATUS[0]}" -eq 0 ] || failed+=("$pass")
  docker compose cp webfast:/var/log/web/ngfw.log "$FTW_OUT/ngfw-$pass.log" >/dev/null 2>&1
  docker compose logs webfast >"$FTW_OUT/webfast-$pass.log" 2>&1
  docker compose down -v >/dev/null 2>&1
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "failed: ${failed[*]} (logs in $FTW_OUT)" >&2
  exit 1
fi
echo "all passed: ${passes[*]}"
