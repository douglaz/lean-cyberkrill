#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Extract only BIP340 public-key columns and check the synthetic x = 5."""
import csv
import io
import json
from pathlib import Path
import urllib.request

REVISION = "927b6de9915c9262615a6399de51b200f81e5aa4"
URL = f"https://raw.githubusercontent.com/bitcoin/bips/{REVISION}/bip-0340/test-vectors.csv"


def main():
    with urllib.request.urlopen(URL) as response:
        source = list(csv.DictReader(io.StringIO(response.read().decode("utf-8"))))
    assert len(source) == 19 and [int(row["index"]) for row in source] == list(range(19))
    rows = [{"index": int(row["index"]), "public_key": row["public key"].lower(),
             "comment": row["comment"]} for row in source]
    output = json.dumps(rows, indent=2) + "\n"
    assert all(set(row) == {"index", "public_key", "comment"} for row in rows)
    assert "secret key" not in output.lower()
    for row in source:
        secret = row["secret key"].strip().lower()
        assert not secret or secret not in output.lower(), "secret-key value in extracted output"
    assert all(len(row["public_key"]) == 64 and len(bytes.fromhex(row["public_key"])) == 32 for row in rows)
    p = 2**256 - 2**32 - 977
    non_residue = pow(132, (p - 1) // 2, p) == p - 1
    assert 5**3 + 7 == 132 and non_residue
    Path(__file__).with_name("bip340-public-keys.json").write_text(output)
    print("BIP340 public keys: 19 rows; only index, public key and comment; no secret-key values")
    print(f"Euler x=5: {non_residue}")


if __name__ == "__main__":
    main()
