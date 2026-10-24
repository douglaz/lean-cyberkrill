# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Extract only the published English entropy and mnemonic columns."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import urllib.request

REVISION = "b57a5ad77a981e743f4167ab2f7927a55c1e82a8"
URL = f"https://raw.githubusercontent.com/trezor/python-mnemonic/{REVISION}/vectors.json"
SHA256 = "fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8"


def main():
    with urllib.request.urlopen(URL) as response:
        data = response.read()
    assert hashlib.sha256(data).hexdigest() == SHA256, "upstream SHA-256 mismatch"
    source = json.loads(data)["english"]
    assert len(source) == 24
    assert all(len(row) == 4 and all(isinstance(x, str) for x in row) for row in source)
    assert Counter(len(row[1].split(" ")) for row in source) == {12: 8, 18: 8, 24: 8}
    rows = [{"entropy": row[0], "mnemonic": row[1]} for row in source]
    output = json.dumps(rows, indent=2) + "\n"
    assert all(set(row) == {"entropy", "mnemonic"} for row in json.loads(output))
    assert all(row[2] not in output and row[3] not in output for row in source)
    destination = Path(__file__).resolve().parent / "test-data/bip39-english-vectors.json"
    destination.write_text(output, encoding="utf-8")
    print("BIP39 English vectors: 24 rows; 8 each of 12/18/24 words; only entropy and mnemonic")


if __name__ == "__main__":
    main()
