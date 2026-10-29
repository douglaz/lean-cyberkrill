#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Construct the nineteen public-point PSBT cases without signing or a scalar."""
import base64
import json
from pathlib import Path


def derive():
    # SEC 2 v2, section 2.4.1, public secp256k1 generator coordinates.
    x = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    y = bytes.fromhex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    negative_y = ((2**256 - 2**32 - 977) - int.from_bytes(y, "big")).to_bytes(32, "big")
    keys = {"02-G": b"\x02" + x, "03-negG": b"\x03" + x,
            "04-G": b"\x04" + x + y, "06-G": b"\x06" + x + y,
            "07-G": b"\x07" + x + y, "07-negG": b"\x07" + x + negative_y,
            "06-negG": b"\x06" + x + negative_y}
    tx = (b"\x02\0\0\0\x01" + bytes(32) + bytes(4) + b"\0" + b"\xff" * 4
          + b"\x01" + bytes(8) + b"\0" + bytes(4))

    def entry(key, value):
        assert len(key) < 253 and len(value) < 253
        return bytes([len(key)]) + key + bytes([len(value)]) + value

    rows = []

    def add(location, forms, success, reason):
        signature = location == "partial"
        tag = b"\x02" if signature else (b"\x06" if location == "input" else b"\x02")
        value = bytes.fromhex("300602010102010101") if signature else bytes(4)
        records = b"".join(entry(tag + keys[form], value) for form in forms)
        raw = b"psbt\xff" + entry(b"\0", tx) + b"\0"
        raw += (b"\0" + records + b"\0") if location == "output" else (records + b"\0\0")
        rows.append({"id": "hybrid-" + location + "-" + "-and-".join(forms),
                     "input_base64": base64.b64encode(raw).decode(),
                     "expected_success": success, "reason": reason})

    for location in ["input", "output"]:
        for form in ["06-G", "07-negG", "02-G", "04-G"]:
            add(location, [form], True, "matching public point")
        for form in ["07-G", "06-negG"]:
            add(location, [form], False, "mismatched hybrid parity")
    for form in ["06-G", "07-negG"]:
        add("partial", [form], False, "strict partial signature public key")
    add("input", ["02-G", "04-G"], False, "same-point duplicate")
    add("input", ["04-G", "06-G"], False, "same-point duplicate")
    add("output", ["02-G", "04-G"], False, "same-point duplicate")
    add("input", ["02-G", "03-negG"], True, "distinct public points")
    add("partial", ["02-G", "04-G"], True, "distinct raw signature keys")
    assert len(rows) == 19 and sum(row["expected_success"] for row in rows) == 10
    assert len({row["id"] for row in rows}) == 19
    return rows


if __name__ == "__main__":
    destination = Path(__file__).with_name("golden") / "hybrid-inputs.json"
    destination.write_text(json.dumps(derive(), indent=2) + "\n", encoding="utf-8")
    print("hybrid inputs: 19/19; predicted success 10, rejection 9")
