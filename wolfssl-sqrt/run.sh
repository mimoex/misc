#!/usr/bin/env bash
# Run inside a disposable clone of https://github.com/wolfSSL/wolfssl
set -euo pipefail
export LIBS="-framework CoreFoundation -framework Security"
REPO="${1:-$PWD}"
MODE="${MODE:-standard}"
JOBS="${JOBS:-4}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"
if [[ ! -f wolfcrypt/src/ecc.c || ! -f wolfssl/wolfcrypt/ecc.h ]]; then
  echo "Error: expected a wolfSSL source checkout: $REPO" >&2
  exit 2
fi
if [[ "$MODE" != standard && "$MODE" != modexp ]]; then
  echo "Usage: MODE=standard|modexp bash $HERE/run.sh /path/to/throwaway-wolfssl" >&2
  exit 2
fi
if [[ ! -x ./configure ]]; then
  ./autogen.sh
fi
if [[ -f Makefile ]]; then
  make distclean >/dev/null 2>&1 || true
fi
python3 "$HERE/expose_sqrt.py" "$PWD"
# With current wolfSSL configure.ac, *explicit* --disable-sp-math or
# --disable-sp-math-all prevents the legacy FastMath macro from being added.
# Request --enable-fastmath and leave both --{en,dis}able-sp-math flags unset:
# configure automatically disables the default SP_MATH_ALL backend.
FLAGS=( --disable-shared --enable-static --disable-sp --disable-sp-asm
        --enable-fastmath --enable-ecc --enable-compkey --disable-ecccustcurves )
if [[ "$MODE" == modexp ]]; then
  CFLAGS='-O2 -DSQRTMOD_USE_MOD_EXP' ./configure "${FLAGS[@]}"
else
  ./configure "${FLAGS[@]}"
fi
# Catch math backend mismatches before running the expensive full build.
if ! grep -Eq '^[[:space:]]*#define[[:space:]]+USE_FAST_MATH([[:space:]]|$)' wolfssl/options.h; then
  echo 'Error: USE_FAST_MATH was not configured; expected the TFM backend.' >&2
  echo 'Inspect the configure summary, options.h, and config.log.' >&2
  grep -E '^#define (USE_FAST_MATH|WOLFSSL_SP_MATH|WOLFSSL_SP_MATH_ALL|WOLFSSL_HAVE_SP_ECC)' wolfssl/options.h || true
  exit 2
fi
if grep -Eq '^[[:space:]]*#define[[:space:]]+(WOLFSSL_SP_MATH|WOLFSSL_SP_MATH_ALL|WOLFSSL_HAVE_SP_ECC)([[:space:]]|$)' wolfssl/options.h; then
  echo 'Error: an SP math backend remains enabled. Check configure flags.' >&2
  grep -E '^#define (USE_FAST_MATH|WOLFSSL_SP_MATH|WOLFSSL_SP_MATH_ALL|WOLFSSL_HAVE_SP_ECC)' wolfssl/options.h || true
  exit 2
fi
printf '\n=== Configured math backend (must be USE_FAST_MATH only) ===\n'
grep -E '^#define (USE_FAST_MATH|WOLFSSL_SP_MATH|WOLFSSL_SP_MATH_ALL|WOLFSSL_HAVE_SP_ECC)' wolfssl/options.h || true
make -j "$JOBS"
if grep -Eq '^[[:space:]]*#define[[:space:]]+WOLFSSL_SP_MATH([[:space:]]|$)' wolfssl/options.h; then
  echo 'Error: WOLFSSL_SP_MATH is active: this is not the intended code path.' >&2
  exit 2
fi
if grep -Eq '^[[:space:]]*#define[[:space:]]+WOLFSSL_CUSTOM_CURVES([[:space:]]|$)' wolfssl/options.h; then
  echo 'Error: WOLFSSL_CUSTOM_CURVES is active; results would differ.' >&2
  exit 2
fi
if [[ ! -f src/.libs/libwolfssl.a ]]; then
  echo 'Error: static library not found: src/.libs/libwolfssl.a' >&2
  exit 2
fi
cc -O2 -I. "$HERE/sqrt_probe.c" src/.libs/libwolfssl.a -lm -pthread -framework CoreFoundation -framework Security -o ./sqrt_probe
cc -O2 -I. "$HERE/ecc_import_probe.c" src/.libs/libwolfssl.a -lm -pthread -framework CoreFoundation -framework Security -o ./ecc_import_probe
printf '\n=== Version/config ===\n'
git rev-parse --short HEAD 2>/dev/null || true
grep -E '^#define (HAVE_COMP_KEY|USE_FAST_MATH|WOLFSSL_SP_MATH|WOLFSSL_SP_MATH_ALL|WOLFSSL_CUSTOM_CURVES)' wolfssl/options.h || true
printf '\n=== Internal sqrt tests ===\n'
set +e
python3 "$HERE/run_tests.py" "$(pwd)/sqrt_probe" --mode "$MODE"
INTERNAL_RC=$?
set -e
printf '\n=== Public API tests ===\n'
python3 - "$(pwd)/ecc_import_probe" <<'PUBLIC_PROBE_PY'
import subprocess
import sys
try:
    p = subprocess.run([sys.argv[1]], timeout=5.0)
except subprocess.TimeoutExpired:
    print('Public API test TIMEOUT after 5 seconds', file=sys.stderr)
    sys.exit(124)
sys.exit(p.returncode)
PUBLIC_PROBE_PY
echo "Internal tests exit code: $INTERNAL_RC"
if [[ "$INTERNAL_RC" -ne 0 ]]; then
  echo 'Internal prime-root test failure detected (expected in modexp mode for p=13).'
  if [[ "$MODE" == standard ]]; then
    exit "$INTERNAL_RC"
  fi
fi
