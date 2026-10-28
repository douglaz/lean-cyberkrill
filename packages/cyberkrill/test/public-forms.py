# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Decompress published SEC1 points; no private scalars or signing arithmetic."""


def forms(compressed):
    point = bytes.fromhex(compressed)
    assert len(point) == 33 and point[0] in (2, 3)
    prime = 2**256 - 2**32 - 977
    x = int.from_bytes(point[1:], "big")
    assert x < prime
    y = pow((x**3 + 7) % prime, (prime + 1) // 4, prime)
    assert y*y % prime == (x**3 + 7) % prime
    if y % 2 != point[0] % 2:
        y = prime - y
    payload = point[1:] + y.to_bytes(32, "big")
    return dict(compressed=compressed, uncompressed=(b"\x04" + payload).hex(),
                hybrid=(bytes([6 + y % 2]) + payload).hex(),
                mismatched=(bytes([7 - y % 2]) + payload).hex())


if __name__ == "__main__":
    import json
    print(json.dumps(forms("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"), indent=2))
