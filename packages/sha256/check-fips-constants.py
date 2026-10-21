# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independently derive FIPS 180-4 sections 4.2.2 and 5.3.3 using exact integers."""

from pathlib import Path
import re


def root_floor(n, degree):
    lo, hi = 0, n + 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if mid**degree <= n:
            lo = mid
        else:
            hi = mid
    assert lo**degree <= n < (lo + 1)**degree
    return lo


def primes(count):
    result = []
    n = 2
    while len(result) < count:
        if all(n % p for p in result if p * p <= n):
            result.append(n)
        n += 1
    return result


def check_constants():
    source = (Path(__file__).parent / "Sha256/Spec.lean").read_text()
    for name, count, degree in [("K", 64, 3), ("H0", 8, 2)]:
        match = re.search(rf"def {name} : Vector Word {count} :=\s*#v\[([^]]+)\]", source)
        assert match, f"missing {name} definition"
        actual = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", match[1])]
        # floor(2^32 * root(p)) minus the integer part scaled by 2^32.
        expected = [root_floor(p << (32 * degree), degree) - (root_floor(p, degree) << 32)
                    for p in primes(count)]
        assert len(actual) == count and actual == expected, f"FIPS {name} mismatch"
        print(f"FIPS {name}: {count}/{count} independently derived")


if __name__ == "__main__":
    check_constants()
