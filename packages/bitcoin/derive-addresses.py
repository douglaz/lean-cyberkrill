# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent, network-free regtest and synthetic legacy known answers.

python3 -I derive-addresses.py [--write]; otherwise compare committed JSON.
The two scripts are BIP350 L186 and L193 at the commit in AddressVectors.lean.
No production Lean implementation is invoked.
"""

import hashlib
import json
from pathlib import Path
import re
import sys


PACKAGE = Path(__file__).resolve().parent
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def polymod(values):
    state = 1
    for value in values:
        top = state >> 25
        state = ((state & 0x1ffffff) << 5) ^ value
        for bit, generator in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if (top >> bit) & 1:
                state ^= generator
    return state


def segwit(hrp, script):
    raw = bytes.fromhex(script)
    version = 0 if raw[0] == 0 else raw[0] - 0x50
    assert len(raw) == raw[1] + 2
    width = (len(raw[2:]) * 8 + 4) // 5
    value = int.from_bytes(raw[2:], "big") << (width * 5 - len(raw[2:]) * 8)
    symbols = [version] + [(value >> (5 * i)) & 31 for i in reversed(range(width))]
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    residue = polymod(expand + symbols + [0] * 6) ^ (1 if version == 0 else 0x2bc830a3)
    checksum = [(residue >> (5 * i)) & 31 for i in reversed(range(6))]
    return hrp + "1" + "".join(CHARSET[n] for n in symbols + checksum)


def checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def base58check(payload):
    raw = payload + checksum(payload)
    n = int.from_bytes(raw, "big")
    digits = ""
    while n:
        n, digit = divmod(n, 58)
        digits = ALPHABET[digit] + digits
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + digits


def main():
    scripts = ["0014751e76e8199196d454941c45d1b3a323f1433bd6",
               "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]
    source = (PACKAGE / "Bitcoin/AddressVectors.lean").read_text()
    pairs = re.findall(r'\("([^"]+)", "([0-9a-f]+)"\)', source)
    assert len(pairs) == 11
    for address, script in pairs:
        assert segwit(address[:2].lower(), script) == address.lower()
    regtest = [dict(name=name, scriptHex=script, address=segwit("bcrt", script))
               for name, script in zip(["v0-p2wpkh", "v1-p2tr"], scripts)]
    negatives = [dict(name="unknown-version", address=base58check(bytes([2]) + bytes(20)),
                      error="unknownVersion")]
    for version in [0, 0x6f, 5, 0xc4]:
        for size in [19, 21]:
            negatives.append(dict(name=f"version-{version}-body-{size}",
                                  address=base58check(bytes([version]) + bytes(size)), error="payloadLength"))
    core = (PACKAGE / "Bitcoin/CoreAddressVectors.lean").read_text()
    original = re.search(r'^  \("([^"]+)"', core, re.M)[1]
    changed = original[:-1] + ("2" if original[-1] == "1" else "1")
    number = 0
    for char in changed:
        number = number * 58 + ALPHABET.index(char)
    raw = bytes(len(changed) - len(changed.lstrip("1"))) + number.to_bytes((number.bit_length() + 7) // 8, "big")
    assert checksum(raw[:-4]) != raw[-4:]
    negatives.append(dict(name="Core-one-character-checksum", address=changed, error="base58Checksum"))
    assert len(negatives) == 10 and len(regtest) == 2
    for filename, rows in [("address-regtest.json", regtest), ("address-negatives.json", negatives)]:
        expected = json.dumps(rows, indent=2) + "\n"
        path = PACKAGE / "test-data" / filename
        if sys.argv[1:] == ["--write"]:
            path.write_text(expected)
        else:
            assert not sys.argv[1:], "usage: derive-addresses.py [--write]"
            assert path.read_text() == expected, filename + " differs"
    print("independent address derivation: 11 BIP cross-checks; regtest 2/2; Base58 negatives 10/10")


if __name__ == "__main__":
    main()
