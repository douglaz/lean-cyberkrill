#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""One production edit per property, runtime reds, exact restoration and greens."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cases import APP

AMOUNTS = "Cyberkrill/Amounts.lean"
APPLICATION = "Cyberkrill/App.lean"
CAPABILITIES = "Cyberkrill/Capabilities.lean"
PRIVATE_OUTPUT = "private_output.c"


def mutations():
    cli = ["python3", "-B", "test/driver.py", "--cli"]
    mnemonic = ["python3", "-B", "test/driver.py", "--mnemonic"]
    def selected(name):
        return [".lake/build/bin/CyberkrillTests", "--check", name]
    rows = [
        ("amount-scaling", APPLICATION, "let a ← parseAmount input", "let a ← parseAmount input\n  let a := Bitcoin.Amount.ofMsat (a.msat * 10)", cli, "amount scaling"),
        ("sats-flooring", APPLICATION, "let sats := a.msat / 1000", "let sats := (a.msat + 500) / 1000", cli, "sats flooring"),
        ("stderr-routing", APPLICATION, "services.stderr (error.message ++", "services.stdout (error.message ++", cli, "output refusal 0 stdout"),
        ("whole-rounding", AMOUNTS, "satsResult a ((a.msat + 500) / 1000)", "satsResult a ((a.msat + 499) / 1000)", selected("whole-round"), "wholeSat half-up"),
        ("whole-tiny", AMOUNTS, "satsResult a ((a.msat + 500) / 1000)", ".ok (Bitcoin.Amount.ofSats ((a.msat + 500) / 1000))", selected("whole-tiny"), "wholeSat tiny"),
        ("floor-tiny", AMOUNTS, "satsResult a (a.msat / 1000)", ".ok (Bitcoin.Amount.ofSats (a.msat / 1000))", selected("floor-tiny"), "floorSat tiny"),
        ("whole-exact", AMOUNTS, "if a.msat % 1000 != 0 then", "if a.msat % 1000 == 0 then", selected("whole-exact"), "exact wholeSat rejects"),
        ("fee-unit", AMOUNTS, "if hasBitcoinUnit s then parseAmount s else .error .feeUnitRequired", "parseAmount s", selected("fee"), "fee unit requirement"),
        ("mnemonic-mapping", APPLICATION, "15 => .ok 20", "15 => .ok 21", mnemonic, "mnemonic entropy mapping"),
        ("entropy-wiring", APPLICATION, "IO.getRandomBytes n.toUSize", "IO.getRandomBytes (n + 1).toUSize", selected("entropy-source"), "entropy production length"),
        ("file-routing", APPLICATION, "some p => { file := some (p, text) }", "some _ => { stdout := text }", mnemonic, "mnemonic file stdout"),
    ]
    for name, field, replacement, assertion in [
        ("cap-pubkey", "isValidPubkey", "fun _ => false", "cap Bitcoin pubkey accepts"),
        ("cap-compress", "compressPubkey", "fun _ => none", "cap Bitcoin compression matches"),
        ("cap-xonly", "isValidXOnlyPubkey", "fun _ => false", "cap Bitcoin xonly accepts"),
        ("cap-der", "isValidDerSignature", "fun _ => false", "cap Bitcoin DER accepts"),
    ]:
        rows.append((name, CAPABILITIES, f"{field} := Secp256k1.{field}", f"{field} := {replacement}", selected(name), assertion))
    for name, old, new, assertion in [
        ("cap-recover", "recover := Secp256k1.recover", "recover := fun _ _ _ => none", "cap BOLT recover L382"),
        ("cap-verify", "verify := Secp256k1.verify", "verify := fun _ _ _ => false", "cap BOLT verify decode"),
        ("cap-sign", "sign := fun hash => Secp256k1.sign hash secret", "sign := fun _ => none", "cap BOLT signature exact"),
        ("cap-point", "isValidPubkey := Secp256k1.isValidPubkey", "isValidPubkey := fun _ => false", "cap BOLT point accepts"),
        ("hash-ripemd", "ripemd160 := Bitcoin.ripemd160", "ripemd160 := Bitcoin.hash160", "cap RIPEMD160"),
        ("hash-hash160", "hash160 := Bitcoin.hash160", "hash160 := Bitcoin.ripemd160", "cap HASH160"),
    ]:
        # Pubkey validation occurs once in each capability. Target the BOLT block.
        if name == "cap-point":
            old = "sign := fun hash => Secp256k1.sign hash secret\n  " + old
            new = "sign := fun hash => Secp256k1.sign hash secret\n  " + new
        rows.append((name, CAPABILITIES, old, new, selected("hashes" if name.startswith("hash-") else name), assertion))
    # Similarly target only Bitcoin's strict field, not BOLT's point field.
    item = rows[11]
    rows[11] = (item[0], item[1], "where\n  " + item[2] + "\n  compressPubkey", "where\n  " + item[3] + "\n  compressPubkey", item[4], item[5])
    for name, old, new, selector, assertion in [
        ("private-mode", ", 0600);", ", 0666);", "mode", "private output mode 0600"),
        ("private-exclusive", "O_CREAT | O_EXCL | O_NOFOLLOW", "O_CREAT | O_NOFOLLOW", "exclusive", "private output exclusive create"),
        ("private-write-error", "if (error != 0)", "if (0)", "write-errors", "private output write failure"),
    ]:
        rows.append((name, PRIVATE_OUTPUT, old, new,
                     ["python3", "-B", "test/private-output.py", selector], assertion))
    assert len(rows) == 24
    return rows


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    os.chdir(APP)
    logs = APP / ".lake/mutations"
    logs.mkdir(parents=True, exist_ok=True)
    paths = [Path(p) for p in [AMOUNTS, APPLICATION, CAPABILITIES, PRIVATE_OUTPUT]]
    originals = {path: path.read_bytes() for path in paths}
    signals = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)

    def write(path, data):
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            path.write_bytes(data)
            assert path.read_bytes() == data, "source byte restoration/write"
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def restore():
        for path, data in originals.items():
            write(path, data)

    def interrupted(signum, _):
        # Restore before waiting on a child or the outer supervisor's deadline.
        restore()
        raise SystemExit(128 + signum)

    for signum in signals:
        signal.signal(signum, interrupted)

    def command(label, args):
        start = time.monotonic()
        p = subprocess.run(["timeout", "--foreground", "180", *args], stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=190)
        for stream in ["stdout", "stderr"]:
            (logs / f"{label}.{stream}").write_bytes(getattr(p, stream))
        (logs / f"{label}.status").write_text(str(p.returncode) + "\n")
        return p, round(time.monotonic() - start, 3)

    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    records = []
    fingerprint_paths = paths + [Path("test/mutate.py"), Path("test/driver.py"), Path("test/compare.py"), Path("test/selftest.py"), Path("test/regressions.py"), Path("test/cases.py"), Path("Main.lean"), Path("lakefile.lean")]
    fingerprint_paths += sorted(Path("CyberkrillTests").glob("*.lean")) + [Path("CyberkrillTests.lean"), Path("test/output-regressions.py"), Path("test/private-output.py"), Path("Cyberkrill/PrivateOutput.lean"), Path("test/golden/private-output-reference.json")]
    fingerprints = {str(p): digest(p) for p in fingerprint_paths}
    try:
        for name, relative, old, new, test, assertion in mutations():
            path = Path(relative)
            original = originals[path]
            source = original.decode()
            assert source.count(old) == 1, f"mutation target is not unique: {name}"
            try:
                write(path, source.replace(old, new, 1).encode())
                compiled, _ = command(name + "-build", build)
                assert compiled.returncode == 0, f"mutation must compile: {name}; see separate logs"
                red, elapsed = command(name + "-red", test)
                assert red.returncode == 1, f"mutation must fail at runtime: {name}"
                output = (red.stdout + red.stderr).decode()
                assert assertion in output and ("assertion failed:" in output or "AssertionError:" in output), f"wrong detecting assertion: {name}"
                records.append(dict(property=name, file=relative, replace=old, with_text=new,
                    build_command=["timeout", "--foreground", "180", *build], build_status=compiled.returncode,
                    command=["timeout", "--foreground", "180", *test], status=red.returncode,
                    detecting_assertion=assertion, seconds=elapsed))
            finally:
                write(path, original)
            green_build, _ = command(name + "-restore-build", build)
            assert green_build.returncode == 0, f"restored build: {name}"
            green, _ = command(name + "-green", test)
            assert green.returncode == 0, f"restored test: {name}"
            records[-1]["restored_status"] = green.returncode
            print(f"{name}: runtime red 1 ({assertion}); restored green 0", flush=True)
        green, elapsed = command("restored-full", ["lake", "test"])
        assert green.returncode == 0, "restored full suite"
        assert {str(p): digest(p) for p in fingerprint_paths} == fingerprints
        record = dict(count=len(records), source_sha256=fingerprints, mutations=records,
                      restored_full=dict(command=["timeout", "--foreground", "180", "lake", "test"], status=0, seconds=elapsed))
        Path("test/golden/mutation-record.json").write_text(json.dumps(record, indent=2) + "\n")
        print("independent mutations: 24/24; restored full suite: exit 0", flush=True)
    finally:
        restore()


if __name__ == "__main__":
    main()
