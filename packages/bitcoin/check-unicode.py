# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Check externally fetched Unicode 17.0.0 casing data, entirely offline.

Usage: python3 -I check-unicode.py UnicodeData.txt SpecialCasing.txt
Conditional locale/context mappings are excluded: Rust uses default casing.
No Unicode data is copied into the repository.
"""

from pathlib import Path
import sys


def main():
    data, special = map(Path, sys.argv[1:])
    mappings = {}
    for line in data.read_text().splitlines():
        fields = line.split(";")
        if fields[13]:
            mappings[int(fields[0], 16)] = [int(fields[13], 16)]
    special_text = special.read_text()
    assert "SpecialCasing-17.0.0.txt" in special_text
    for line in special_text.splitlines():
        fields = line.split("#", 1)[0].strip().split(";")
        if len(fields) >= 5 and not fields[4].strip():
            mappings[int(fields[0], 16)] = [int(x, 16) for x in fields[1].split()]
    ascii_images = {cp: dest for cp, dest in mappings.items()
                    if cp >= 128 and dest and all(x < 128 for x in dest)}
    assert ascii_images == {0x212A: [ord("k")]}, ascii_images
    print("Unicode 17.0.0 default lowercase: non-ASCII to entirely ASCII: U+212A -> k (1/1)")


if __name__ == "__main__":
    main()
