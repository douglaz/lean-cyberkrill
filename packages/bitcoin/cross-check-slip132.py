# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Derive independent public-version swaps using Python base58, never the port."""
import json
from pathlib import Path
import base58

PACKAGE = Path(__file__).resolve().parent
# cyberkrill-core/src/slip132.rs:9-20 at 27cad1faba86260b06665a89f0af5134d23525c2.
VERSIONS = [("xpub", "0488b21e"), ("ypub", "049d7cb2"), ("zpub", "04b24746"),
            ("tpub", "043587cf"), ("upub", "044a5262"), ("vpub", "045f1cf6")]


def main():
    assert base58.__version__ == "2.1.1"
    sources = json.loads((PACKAGE / "test-data/bip32-public-vectors.json").read_text())
    assert len(sources) == 12
    rows = []
    for source in sources:
        payload = base58.b58decode_check(source)
        assert len(source) == 111 and source.startswith("xpub")
        assert len(payload) == 78 and payload[:4] == bytes.fromhex("0488b21e")
        for prefix, version in VERSIONS:
            swapped = bytes.fromhex(version) + payload[4:]
            encoded = base58.b58encode_check(swapped).decode("ascii")
            assert encoded.startswith(prefix)
            assert base58.b58decode_check(encoded) == swapped
            rows.append(dict(source=source, prefix=prefix, versionHex=version, encoded=encoded))
    assert len(rows) == 72
    golden_inputs = [r["encoded"] for r in rows if r["prefix"] in ("ypub", "zpub", "upub", "vpub")]
    assert len(golden_inputs) == 48
    target = PACKAGE / "test-data/slip132-derived.json"
    target.write_text(json.dumps(rows, indent=2) + "\n")
    target.with_suffix(".json.provenance").write_text(
        "Producer: cross-check-slip132.py with Python base58 2.1.1 (MIT).\n"
        "Command: nix shell --impure --expr 'let pkgs = import (builtins.getFlake "
        "(toString ./.)).inputs.nixpkgs {}; in pkgs.python3.withPackages (p: [p.base58])' "
        "-c python3 -I packages/bitcoin/cross-check-slip132.py\n"
        "Inputs: BIP32 test vectors 1 and 2, bip-0032.mediawiki at "
        "130b8e0fa7f30fa45532f080b87b8db27a79e46e (BSD-2-Clause; Bitcoin/LICENSE-bips).\n"
        "Source: https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0032.mediawiki\n"
        "Table: https://github.com/douglaz/cyberkrill/blob/27cad1faba86260b06665a89f0af5134d23525c2/cyberkrill-core/src/slip132.rs#L9-L20\n"
        "Changes: derived: version bytes swapped; last 74 bytes unchanged.\n"
        "Order: each of the 12 source lines, then xpub, ypub, zpub, tpub, upub, vpub.\n")
    print("Python base58 2.1.1; BIP32 public vectors: 12/12")
    print("SLIP-132 independent conversions: 72/72")
    print("SLIP-132 golden inputs: 48/48")


if __name__ == "__main__":
    main()
