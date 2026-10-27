#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Offline executable, exact-oracle and golden checks; no random mnemonic."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cases import APP, ROOT, cases
from compare import Comparator, exact_json
from selftest import selftest

EXE = APP / ".lake/build/bin/cyberkrill"
TEST = APP / ".lake/build/bin/CyberkrillTests"


def count(name, rows, expected):
    assert len(rows) == expected, f"{name} count"
    print(f"{name}: {len(rows)}/{expected}", flush=True)


def run(args, input=None):
    payload = input.encode("utf-8") if isinstance(input, str) else input
    proc = subprocess.run(args, cwd=APP, input=payload, stdin=subprocess.DEVNULL if input is None else None,
                          capture_output=True, timeout=30)
    return dict(status=proc.returncode, stdout=proc.stdout.decode("utf-8"), stderr=proc.stderr.decode("utf-8"))


def fixtures():
    manifest = json.loads((APP / "test/golden/fixture-digests.json").read_text())
    count("external fixture digests", manifest, 5)
    for relative, digest in manifest.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest, f"fixture digest: {relative}"
    cli = json.loads((ROOT / "packages/bitcoin/test-data/cli.json").read_text())
    parser = json.loads((ROOT / "packages/bitcoin/test-data/cyberkrill-amounts.json").read_text())
    signatures = json.loads((ROOT / "packages/secp256k1/bolt11.json").read_text())
    count("existing amount cases", cli, 124)
    count("existing parser-only captures", parser, 124)
    count("existing secp signatures", signatures, 16)
    source = (APP / "Cyberkrill/App.lean").read_text()
    assert "entropy := fun n => IO.getRandomBytes n.toUSize" in source, "entropy-source-wiring"
    assert "Cyberkrill.runWith Cyberkrill.version Cyberkrill.productionServices args" in (APP / "Main.lean").read_text(), "entropy-dispatch-wiring"


def goldens():
    refs = json.loads((APP / "test/golden/reference.json").read_text())
    count("real CLI reference captures", refs, 179)
    assert [{k: v for k, v in r.items() if k != "result"} for r in refs] == cases(), "capture input inventory"
    amounts = json.loads((APP / "test/golden/exact-amount-diffs.json").read_text())
    refusals = json.loads((APP / "test/golden/named-refusals.json").read_text())
    count("exact amount entries", amounts, 20)
    count("named amount refusals", refusals, 29)
    comparator = Comparator(amounts, refusals)
    for row in refs:
        actual = run([str(EXE), *row["args"]])
        comparator.compare(row, row["result"], actual)
        if row["id"] == "version":
            assert exact_json(actual["stdout"]) == {"version": "0.1.0"}, "package version"
    comparator.finish()


def executable():
    from importlib import import_module
    import_module("output-regressions").public_checks()
    accepted = [(".5", 50000000000), ("5.", 500000000000), ("+5msat", 5),
                ("+0.5btc", 50000000000), ("+0.5", 50000000000),
                ("-0", 0), ("-0.0btc", 0), ("-0.000sat", 0), ("0.5000sat", 500)]
    count("direct accepted spellings", accepted, 9)
    for text, n in accepted:
        p = run([str(EXE), "convert-amount", *(["--"] if text.startswith("-") else []), text])
        assert p["status"] == 0 and p["stderr"] == "", "direct spelling status"
        j = exact_json(p["stdout"])
        assert set(j) == {"input", "btc", "sats", "msats"} and j["input"] == text and j["msats"] == n, "amount scaling"
    invalid = [("", "empty"), ("bad", "invalidNumber"), ("-1btc", "negative"),
               ("-0msat", "invalidNumber"), ("0.0001sat", "subMillisatoshi"),
               ("1e3", "invalidNumber"), ("inf", "invalidNumber"),
               ("nan", "invalidNumber"), ("infinity", "invalidNumber"),
               ("18446744073709551616msat", "millisatoshiOverflow")]
    count("named CLI rejection classes", invalid, 10)
    for text, error in invalid:
        p = run([str(EXE), "convert-amount", "--", text])
        assert p["status"] == 1 and p["stdout"] == "" and p["stderr"].startswith(error + ":"), "stderr error routing"
    fiat = ["100USD", "2081.74BRL", "1,000 USD", "-bad1usd", " 1 EUR "]
    count("port-only fiat refusals", fiat, 5)
    for value in fiat:
        p = run([str(EXE), "convert-amount", "--", value])
        assert p["status"] == 1 and not p["stdout"] and p["stderr"].startswith("fiatNotSupported:"), "fiat offline refusal"
    help_cases = [[], ["--help"], ["version", "--help"], ["convert-amount", "--help"], ["generate-mnemonic", "-h"]]
    count("executable help", help_cases, 5)
    for args in help_cases:
        p = run([str(EXE), *args])
        assert p["status"] == 0 and p["stderr"] == "" and "USAGE:" in p["stdout"], "help boundary"
        assert "--electrum" not in p["stdout"] and "--esplora" not in p["stdout"], "truthful help"
    unsupported = [["--esplora", "unused"], ["generate-mnemonic", "--entropy", "unused"],
                   ["generate-mnemonic", "-o"], ["generate-mnemonic", "-w"],
                   ["generate-mnemonic", "extra"], ["generate-mnemonic", "-o", "a", "--output", "b"]]
    count("additional unsupported options", unsupported, 6)
    for args in unsupported:
        p = run([str(EXE), *args])
        assert p["status"] == 1 and p["stdout"] == "" and p["stderr"].startswith("invalidArguments:"), "unsupported option boundary"
    p = run([str(EXE), "convert-amount", "1500msat", "--as", "sats"])
    assert p == dict(status=0, stdout="1\n", stderr="[convert-amount] note: input has fractional satoshis (1500 msat); --as sats floors to 1 sat\n"), "sats flooring"


def mnemonic(plus=False):
    wordlist = (ROOT / "packages/bitcoin/Bitcoin/bip39-english.txt").read_text().splitlines()
    count("independent oracle wordlist", wordlist, 2048)
    published = json.loads((ROOT / "packages/bitcoin/test-data/bip39-english-vectors.json").read_text())
    count("published exact mnemonics", published, 24)

    def oracle(entropy):
        bits = ''.join(f'{b:08b}' for b in entropy)
        checksum = f'{hashlib.sha256(entropy).digest()[0]:08b}'[:len(entropy) // 4]
        combined = bits + checksum
        return ' '.join(wordlist[int(combined[i:i+11], 2)] for i in range(0, len(combined), 11))

    rows = []
    for i, r in enumerate(published):
        assert oracle(bytes.fromhex(r['entropy'])) == r['mnemonic'], f"oracle published exact case {i}"
        rows.append(dict(entropy=r['entropy'], mnemonic=r['mnemonic'], words=len(r['mnemonic'].split())))
    sources = [r for r in published if len(bytes.fromhex(r['entropy'])) == 32]
    count("derived entropy sources", sources, 8)
    for width, words in [(20, 15), (28, 21)]:
        derived = [dict(entropy=r['entropy'][:width*2], mnemonic=oracle(bytes.fromhex(r['entropy'])[:width]), words=words) for r in sources]
        count(f"derived exact {words}", derived, 8)
        rows.extend(derived)
    count("injected production successes", rows, 40)
    p = run([str(TEST), "--injected-plus" if plus else "--injected"], json.dumps(rows) + "\n")
    # Never print the payload, even on failure.
    assert p["status"] == 0, "mnemonic injected path: " + p["stderr"]
    print(p["stdout"], end="")


def main():
    home = Path(tempfile.mkdtemp(prefix="cli-tests-", dir=os.environ["TMPDIR"]))
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home)
    try:
        if sys.argv[1:] == ["--mnemonic"]:
            mnemonic()
        elif sys.argv[1:] == ["--cli"]:
            executable()
        elif sys.argv[1:] == ["--harness"]:
            selftest()
        else:
            assert not sys.argv[1:]
            fixtures(); selftest(); goldens(); executable(); mnemonic()
            from regressions import main as regression_checks
            regression_checks()
    finally:
        if old_home is not None: os.environ["HOME"] = old_home
        else: os.environ.pop("HOME", None)
        home.rmdir()


if __name__ == "__main__":
    main()
