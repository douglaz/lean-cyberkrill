# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independently derive synthetic Base58Check answers with Python hashlib.

Run with python3 -I; --write regenerates the committed output, otherwise compare.
No network, third-party modules, key material or address-shaped payloads.
"""

import hashlib
import json
from pathlib import Path
import re
import sys


PACKAGE = Path(__file__).resolve().parent
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(data):
    zeros = len(data) - len(data.lstrip(b"\0"))
    n = int.from_bytes(data, "big")
    chars = []
    while n:
        n, digit = divmod(n, 58)
        chars.append(ALPHABET[digit])
    return "1" * zeros + "".join(reversed(chars))


def main():
    vectors = re.findall(r'^\s*\("([0-9a-fA-F]*)", "([^"]*)"\)',
                         (PACKAGE / "Bitcoin/Base58Vectors.lean").read_text(), re.M)
    assert len(vectors) == 21
    for raw, encoded in vectors:
        assert base58(bytes.fromhex(raw)) == encoded, raw
    print("independent base58 vectors: 21/21")
    payloads = [("empty", b""), ("leading-zeros", bytes([0, 0, 1, 2, 3])),
                ("all-zeros", bytes(3)), ("long", bytes(range(66, 106)))]
    answers = []
    for name, payload in payloads:
        assert len(payload) not in [21, 33, 34, 78]
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        answers.append(dict(name=name, payloadHex=payload.hex(),
                            checksumHex=checksum.hex(), encoded=base58(payload + checksum)))
    output = PACKAGE / "test-data/base58check.json"
    encoded = json.dumps(answers, indent=2) + "\n"
    if sys.argv[1:] == ["--write"]:
        output.write_text(encoded)
    else:
        assert not sys.argv[1:], "usage: derive-base58check.py [--write]"
        assert output.read_text() == encoded, "committed answers differ"
    print("independent Base58Check answers: 4/4")


if __name__ == "__main__":
    main()
