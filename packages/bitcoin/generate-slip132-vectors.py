# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Extract only BIP32 test vectors 1 and 2's public extended keys."""
import hashlib
import json
from pathlib import Path
import re
import urllib.request

REVISION = "130b8e0fa7f30fa45532f080b87b8db27a79e46e"
URL = f"https://raw.githubusercontent.com/bitcoin/bips/{REVISION}/bip-0032.mediawiki"
SHA256 = "e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f"
PACKAGE = Path(__file__).resolve().parent


def main():
    with urllib.request.urlopen(URL) as response:
        source = response.read()
    assert len(source) == 28032 and hashlib.sha256(source).hexdigest() == SHA256
    text = source.decode("utf-8")
    assert "Authors: Pieter Wuille <pieter.wuille@gmail.com>" in text
    assert "License: BSD-2-Clause" in text
    assert "==Copyright==\n\nThis BIP is licensed under the 2-clause BSD license." in text
    rows, excluded = [], []
    for vector in (1, 2):
        section = text.split(f"===Test vector {vector}===")[1].split("===Test vector")[0]
        public = re.findall(r"ext pub: (\w+)", section)
        private = re.findall(r"ext prv: (\w+)", section)
        assert len(public) == len(private) == 6
        rows.extend(public)
        excluded.extend(private)
    assert len(rows) == 12 and len(set(rows)) == 12
    assert all(len(s) == 111 and re.fullmatch(r"xpub[1-9A-HJ-NP-Za-km-z]+", s) for s in rows)
    output = json.dumps(rows, indent=2) + "\n"
    assert all(s not in output for s in excluded)
    target = PACKAGE / "test-data/bip32-public-vectors.json"
    target.write_text(output, encoding="utf-8")
    target.with_suffix(".json.provenance").write_text(
        f"Source: {URL}\nCommit: {REVISION}\nPath: bip-0032.mediawiki\n"
        f"Source SHA-256: {SHA256}\n"
        "Authors: Pieter Wuille <pieter.wuille@gmail.com>\n"
        "Licence: BSD-2-Clause; see Bitcoin/LICENSE-bips.\n"
        "Changes: extracted: the ext pub lines of test vectors 1 and 2.\n"
        "Order: vector 1's six lines, then vector 2's six lines, in published order.\n"
        "No private columns or complete source document retained.\n", encoding="utf-8")
    print("BIP32 public vectors: 12/12")


if __name__ == "__main__":
    main()
