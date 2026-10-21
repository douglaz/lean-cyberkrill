#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Extract canonical BOLT #11 signatures and compute their signing digests."""
import hashlib
import json
from pathlib import Path
import urllib.request

REVISION = "191462825ae341f0a27098765c075f01ca9bc6c2"
URL = f"https://raw.githubusercontent.com/lightning/bolts/{REVISION}/11-payment-encoding.md"
HEADINGS = [382, 410, 438, 466, 491, 516, 554, 579, 602, 625, 648, 682, 704, 707, 735, 762]
ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def pack(words):
    value = 0
    bits = 0
    result = bytearray()
    for word in words:
        value = (value << 5) | word
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((value >> bits) & 255)
    if bits:
        result.append((value << (8 - bits)) & 255)
    return bytes(result)


def main():
    with urllib.request.urlopen(URL) as response:
        lines = response.read().decode("utf-8").splitlines()
    assert len(lines) == 868
    vectors = []
    for heading in HEADINGS:
        invoice = lines[heading].strip().removeprefix("> ").strip("`").lower()
        hrp, data = invoice.rsplit("1", 1)
        assert hrp.startswith(("lnbc", "lntb")), (heading, invoice)
        words = [ALPHABET.index(char) for char in data]
        signed, signature = words[:-110], pack(words[-110:-6])
        assert len(signature) == 65 and signature[64] <= 3
        vectors.append({"line": heading,
                        "digest": hashlib.sha256(hrp.encode("ascii") + pack(signed)).hexdigest(),
                        "signature": signature[:64].hex(), "recid": signature[64]})
    destination = Path(__file__).with_name("bolt11.json")
    destination.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {len(vectors)} BOLT #11 vectors to {destination}")


if __name__ == "__main__":
    main()
