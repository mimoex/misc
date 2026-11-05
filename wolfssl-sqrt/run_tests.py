#!/usr/bin/env python3
"""Bounded correctness/termination tests for sqrt_probe. Runs on macOS/Linux."""
import argparse
import subprocess
import sys


def run(path, name, a, p, timeout):
    try:
        result = subprocess.run([path, f'{a:x}', f'{p:x}'],
                                text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f'{name:28} TIMEOUT ({timeout:.1f}s)')
        return 'TIMEOUT'
    lines = ' '.join(result.stdout.strip().splitlines())
    if result.returncode != 0:
        print(f'{name:28} TEST_ERROR rc={result.returncode} stderr={result.stderr.strip()}')
        return 'TEST_ERROR'
    if 'sqrt_ret=0' in result.stdout and 'valid_root=1' in result.stdout:
        status = 'CORRECT_ROOT'
    elif 'sqrt_ret=0' in result.stdout and 'valid_root=0' in result.stdout:
        status = 'INCORRECT_ROOT'
    elif 'sqrt_ret=' in result.stdout:
        status = 'REJECTED'
    else:
        status = 'TEST_ERROR'
    print(f'{name:28} {status:16} {lines}')
    return status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('probe', help='path to compiled ./sqrt_probe')
    parser.add_argument('--mode', choices=['standard', 'modexp'], default='standard')
    parser.add_argument('--timeout', type=float, default=2.0)
    args = parser.parse_args()

    # All positive tests use actual primes.
    prime_cases = [('prime_11_a9', 9, 11),
                   ('prime_13_a4', 4, 13),
                   ('prime_17_a4', 4, 17)]
    bad = 0
    for name, a, p in prime_cases:
        result = run(args.probe, name, a, p, args.timeout)
        if result != 'CORRECT_ROOT':
            bad += 1

    # For p=13, 2 is not a quadratic residue.
    nonres = run(args.probe, 'prime_13_a2_no_root', 2, 13, args.timeout)
    if args.mode == 'standard' and nonres != 'REJECTED':
        bad += 1

    # Invalid moduli: observable behavior, NOT proof of an exploitable bug.
    run(args.probe, 'composite_15_a4', 4, 15, args.timeout)
    run(args.probe, 'composite_25_a4', 4, 25, args.timeout)

    # Odd square: Jacobi(z, q^2) cannot be -1 for z coprime to q.
    # This explores the Z search and is deliberately bounded by subprocess timeout.
    q = (1 << 127) - 1
    run(args.probe, 'large_composite_square', 4, q * q, args.timeout)

    print('\nInterpretation: a timeout for an invalid composite modulus does NOT')
    print('establish that any attacker-controlled certificate reaches this function.')
    if args.mode == 'modexp':
        print('The modexp variant must also return correct roots for prime moduli;')
        print('a wrong result for prime_13_a4 is a separate correctness issue.')
    if bad:
        print(f'FAIL: {bad} expected prime-modulus test(s) failed')
        return 1
    print('Prime-modulus test checks: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
