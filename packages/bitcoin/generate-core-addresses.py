# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Fetch pinned Core data outside the tree, extract only public legacy addresses.

python3 -I generate-core-addresses.py [--write]; default compares a fresh fetch.
The source contains private entries: never print its contents or retain its fetch.
"""

from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


PACKAGE = Path(__file__).resolve().parent
COMMIT = "9be056a8a72b624dae9623b2f7bded92c2a21c91"
SOURCE = "src/test/data/key_io_valid.json"
URL = f"https://raw.githubusercontent.com/bitcoin/bitcoin/{COMMIT}/{SOURCE}"
SHA256 = "90bd1d35d12763e0d00c5400b2c9fe551e532a821e1e466c20cad3aced70a7fe"


def main():
    root = Path(tempfile.mkdtemp(prefix="lck-address-core-", dir="/var/tmp"))
    fetch = root / "key_io_valid.json"
    try:
        subprocess.run(["curl", "-fL", URL, "-o", str(fetch)], check=True)
        assert hashlib.sha256(fetch.read_bytes()).hexdigest() == SHA256, "source SHA-256 mismatch"
        data = json.loads(fetch.read_bytes())
        assert len(data) == 70
        assert sum(entry[2]["isPrivkey"] for entry in data) == 16
        public = []
        for address, script, meta in data:
            if meta["isPrivkey"]:
                continue
            pkh = len(script) == 50 and script.startswith("76a914") and script.endswith("88ac")
            sh = len(script) == 46 and script.startswith("a914") and script.endswith("87")
            if pkh or sh:
                public.append((address, script, meta["chain"]))
        assert len(public) == 22
        assert Counter(chain for _, _, chain in public) == dict(main=6, testnet4=6, signet=6, regtest=4)
        chunks = [
            f"-- Extracted from https://github.com/bitcoin/bitcoin @ {COMMIT}, {SOURCE}; "
            "MIT, see Bitcoin/LICENSE-bitcoin-core; extracted and reformatted (public P2PKH/P2SH only).",
            "namespace BitcoinTests.CoreAddressVectors", "",
            "def legacy : Array (String × String × String) := #[",
            ",\n".join("  (" + ", ".join(json.dumps(s) for s in entry) + ")" for entry in public) + "]",
            "", "end BitcoinTests.CoreAddressVectors", "",
        ]
        expected = "\n".join(chunks)
        target = PACKAGE / "Bitcoin/CoreAddressVectors.lean"
        if sys.argv[1:] == ["--write"]:
            target.write_text(expected)
        else:
            assert not sys.argv[1:], "usage: generate-core-addresses.py [--write]"
            assert target.read_text() == expected, "Core vectors differ"
        print("Core public Base58 vectors: 22/22; main/testnet4/signet/regtest = 6/6/6/4")
    finally:
        if fetch.exists():
            fetch.unlink()
            print(f"unlink {fetch}: exit 0")
        root.rmdir()
        print(f"rmdir {root}: exit 0")
        assert not root.exists()


if __name__ == "__main__":
    main()
