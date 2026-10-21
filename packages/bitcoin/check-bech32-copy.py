# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compare exactly the forty codec strings with separately fetched pinned BIPs.

Usage: python3 -I check-bech32-copy.py SOURCE_DIRECTORY [--write]
The checker performs no network access. --write creates the vector file once.
"""

import json
from pathlib import Path
import re
import sys


COMMIT = "130b8e0fa7f30fa45532f080b87b8db27a79e46e"
PACKAGE = Path(__file__).resolve().parent
PROVENANCE = (
    f"-- Extracted from https://github.com/bitcoin/bips @ {COMMIT}, "
    "bip-0173.mediawiki L277-283, L291-302; bip-0350.mediawiki L156-162, L167-180; "
    "BSD-2-Clause, see LICENSE-bips; extracted and reformatted."
)
SETS = [
    ("bech32Valid", "bip-0173.mediawiki", 277, 283, 7),
    ("bech32Invalid", "bip-0173.mediawiki", 291, 302, 12),
    ("bech32mValid", "bip-0350.mediawiki", 156, 162, 7),
    ("bech32mInvalid", "bip-0350.mediawiki", 167, 180, 14),
]


def extract(source, start, end):
    strings = []
    for line in source.splitlines()[start - 1:end]:
        match = re.match(r"\* (?:0x([0-9A-Fa-f]{2}) \+ )?<tt>([^<]*)</tt>(.*)", line)
        assert match, line
        prefix, value, after = match.groups()
        if prefix:
            value = chr(int(prefix, 16)) + value
        if after.startswith(" + 0xFF"):
            value += chr(255)
        strings.append(value)
    return strings


def quote(value):
    quoted = json.dumps(value, ensure_ascii=False)
    for point in [0x7f, 0x80, 0xff]:
        quoted = quoted.replace(chr(point), f"\\x{point:02x}")
    return quoted


def main():
    directory = Path(sys.argv[1])
    chunks = [PROVENANCE, "namespace BitcoinTests.Bech32Vectors", ""]
    count = 0
    for name, path, start, end, pinned in SETS:
        source = (directory / path).read_text()
        assert "  License: BSD-2-Clause\n" in source
        strings = extract(source, start, end)
        assert len(strings) == pinned
        chunks.append(f"def {name} : Array String := #[")
        chunks.append(",\n".join("  " + quote(value) for value in strings) + "]")
        chunks.append("")
        count += len(strings)
    chunks.append("end BitcoinTests.Bech32Vectors")
    expected = "\n".join(chunks) + "\n"
    path = PACKAGE / "Bitcoin/Bech32Vectors.lean"
    if sys.argv[2:] == ["--write"]:
        assert not path.exists(), "--write only creates a new vector file"
        path.write_text(expected)
    else:
        assert not sys.argv[2:], "unexpected arguments"
    assert path.read_text() == expected, "vector file differs from the pinned extraction"
    assert count == 40
    print("bech32 vector copy: 40/40; exact pinned line ranges and first-line provenance")


if __name__ == "__main__":
    main()
