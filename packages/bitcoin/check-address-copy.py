# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compare segwit vectors against exact lines in separately fetched pinned BIPs.

python3 -I check-address-copy.py SOURCE_DIRECTORY [--write]
No network access; --write creates the vector file once.
"""

import json
from pathlib import Path
import re
import sys


PACKAGE = Path(__file__).resolve().parent
COMMIT = "130b8e0fa7f30fa45532f080b87b8db27a79e46e"
PROVENANCE = (
    f"-- Extracted from https://github.com/bitcoin/bips @ {COMMIT}, "
    "bip-0350.mediawiki L186-193, L197-211; bip-0173.mediawiki L306-311, L315-324; "
    "BSD-2-Clause, see Bitcoin/LICENSE-bips; extracted and reformatted."
)
SETS = [
    ("bip350Valid", "bip-0350.mediawiki", list(range(186, 194)), True, 8),
    ("bip173V0", "bip-0173.mediawiki", [306, 307, 311], True, 3),
    ("bip173Replaced", "bip-0173.mediawiki", [308, 309, 310], False, 3),
    ("bip350Invalid", "bip-0350.mediawiki", list(range(197, 212)), False, 15),
    ("bip173Invalid", "bip-0173.mediawiki", list(range(315, 325)), False, 10),
]


def main():
    directory = Path(sys.argv[1])
    chunks = [PROVENANCE, "namespace BitcoinTests.AddressVectors", ""]
    total = 0
    for name, filename, lines, paired, count in SETS:
        source = (directory / filename).read_text()
        assert "  License: BSD-2-Clause\n" in source
        entries = []
        for line in lines:
            text = source.splitlines()[line - 1]
            strings = re.findall(r"<tt>([^<]*)</tt>", text)
            assert len(strings) >= (2 if paired else 1), (filename, line)
            if paired:
                address, script = strings[:2]
                assert re.fullmatch(r"[0-9a-fA-F]+", script)
                entries.append(f"  ({json.dumps(address)}, {json.dumps(script)})")
            else:
                entries.append("  " + json.dumps(strings[0]))
        assert len(entries) == count
        typ = "(String × String)" if paired else "String"
        chunks.extend([f"def {name} : Array {typ} := #[", ",\n".join(entries) + "]", ""])
        total += count
    chunks.append("end BitcoinTests.AddressVectors")
    expected = "\n".join(chunks) + "\n"
    target = PACKAGE / "Bitcoin/AddressVectors.lean"
    if sys.argv[2:] == ["--write"]:
        assert not target.exists(), "--write only creates a new file"
        target.write_text(expected)
    else:
        assert not sys.argv[2:], "unexpected arguments"
    assert target.read_text() == expected, "address vector extraction differs"
    assert total == 39
    print("address BIP copy: 39/39; exact pinned lines and first-line provenance")


if __name__ == "__main__":
    main()
