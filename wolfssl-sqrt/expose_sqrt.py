#!/usr/bin/env python3
"""Test-only modification: expose ecc.c's internal mp_sqrtmod_prime symbol.

Run ONLY in a disposable wolfSSL checkout. This changes the source, not
production code. The original implementation and its call sites are unchanged.
"""
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 2:
    sys.exit('Usage: python3 expose_sqrt.py /path/to/wolfssl')
root = Path(sys.argv[1]).resolve()
source = root / 'wolfcrypt' / 'src' / 'ecc.c'
if not source.exists():
    sys.exit(f'not found: {source}')

before = source.read_text(encoding='utf-8')
old = 'static int mp_sqrtmod_prime('
new = 'int mp_sqrtmod_prime('
expected_count = 2  # forward declaration + implementation, in verified master

# Do not overwrite unrelated changes; allow only this test's own repeatable patch.
if (root / '.git').exists():
    baseline = subprocess.run(
        ['git', 'show', 'HEAD:wolfcrypt/src/ecc.c'], cwd=root,
        capture_output=True, text=True, check=False)
    if baseline.returncode != 0:
        sys.exit('Cannot verify a clean tracked ecc.c; no changes made.')
    clean = baseline.stdout
    if clean.count(old) != expected_count:
        sys.exit('Source differs from expected upstream declarations; no changes made.')
    if before == clean.replace(old, new):
        print("Already patched; source contains only this lab's test-only change.")
        sys.exit(0)
    if before != clean:
        sys.exit('Refusing to patch modified ecc.c. Use a disposable clean clone.')

if before.count(old) != expected_count:
    sys.exit(f'Expected {expected_count} declarations; found {before.count(old)}. '
             'Review the target version manually; no changes made.')
source.write_text(before.replace(old, new), encoding='utf-8')
print('Patched ecc.c: removed static from mp_sqrtmod_prime declaration and definition.')
print('Restore with: git restore -- wolfcrypt/src/ecc.c (after finishing the lab)')
