#!/usr/bin/env bash
# The filter's go-ftw tests against a webfast binary, in Docker (ci/ftw/compose.yaml: the binary
# on alpine, albedo as the backend, go-ftw; the images pinned there).
#
#   WEBFAST_BIN=path/to/webfast scripts/ftw-run.sh [all] [cve] [crs]     (none named: all, cve)
#
# all: every built-in set, as the filter ships; the tests of ci/ftw/ftw-all.yaml's `ignore` are
#      skipped, each for its reason. cve: the cve set alone, its tests only, nothing ignored.
# crs: the bundled OWASP CRS (a binary built with the ngfw-crs feature) on the CRS release's own
#      regression tests, at their settings (ci/ftw/ngfw-crs.yaml); the tests are CRS_TESTS (a
#      directory), or fetched from the release webfast-ngfw-crs bundles, its checksum checked.
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

# The CRS's regression tests of the release bundled (crates/webfast-ngfw-crs/src/lib.rs).
crs_tests() {
  if [ -n "${CRS_TESTS:-}" ]; then
    CRS_TESTS=$(realpath "$CRS_TESTS") || return 1
    export CRS_TESTS
    return 0
  fi
  local version sum
  version=$(sed -n 's/^pub const CRS_VERSION: &str = "\(.*\)";/\1/p' ../../crates/webfast-ngfw-crs/src/lib.rs)
  sum=a4bb3688ef6205b64471a9ccbf0d7b024eb8edf39b97c6f6c0006e7a948f8550
  [ "$version" = 4.30.0 ] || { echo "the checksum here is 4.30.0's, the crate bundles $version" >&2; return 1; }
  if [ ! -d crs-tests ]; then
    curl -fsSL -o crs.tar.gz "https://github.com/coreruleset/coreruleset/archive/refs/tags/v$version.tar.gz" || return 1
    echo "$sum  crs.tar.gz" | sha256sum -c - >/dev/null || { echo "crs.tar.gz: not the release's checksum" >&2; return 1; }
    mkdir -p crs-tests
    tar -xzf crs.tar.gz -C crs-tests --strip-components=4 "coreruleset-$version/tests/regression/tests" || return 1
    rm -f crs.tar.gz
  fi
  CRS_TESTS=$(realpath crs-tests)
  export CRS_TESTS
}
failed=()
for pass in "${passes[@]}"; do
  exclude=()
  case "$pass" in
    all) dir=/tests ;;
    cve) dir=/tests/rules/cve ;;
    crs)
      dir=/crs-tests
      crs_tests || { failed+=("$pass"); continue; }
      # The rules the engine does not load: the blocking evaluation (949, the filter decides) and
      # the response phases' (95x, 959, 980). 921140-1 writes a raw CR/LF in a header, which go-ftw
      # refuses to send (and stops the run).
      exclude=(--exclude '^(921140-1|949[0-9]{3}-[0-9]+|95[0-9]{4}-[0-9]+|980[0-9]{3}-[0-9]+)$')
      ;;
    *) echo "unknown pass $pass (all, cve, crs)" >&2; exit 2 ;;
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
    --show-failures-only --read-timeout 5s "${exclude[@]}" \
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
