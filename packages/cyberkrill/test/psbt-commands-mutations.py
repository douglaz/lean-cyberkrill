#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compiled production edits, named runtime reds and byte-exact restoration."""
import hashlib
from contextlib import chdir
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from evidence import write_record
from cases import APP, ROOT
from network import run_owned

DEST = APP / "test/golden/psbt-commands-mutation-record.json"
LOGS = APP / ".lake/validation/psbt-mutations" / str(time.time_ns())


def mutations():
    source = "Cyberkrill/PsbtCommands.lean"
    app = "Cyberkrill/App.lean"
    core = "Cyberkrill/CoreRpc.lean"
    rows = [
        ("explicit-order", source, 'result := result.push { txid := parts[0]!, vout }',
         'result := #[{ txid := parts[0]!, vout }] ++ result', ["replay", "create-explicit-1sat"], "PSBT CLI success"),
        ("expansion-empty", source, 'if result.isEmpty then return .error', 'if false then return .error', ["probes", "empty-expansion"], "PSBT probe request order/stopping"),
        ("dedup-scope", source, 'result := result.push { txid := u.txid, vout := u.vout }',
         'if !result.any (fun i => i.txid == u.txid && i.vout == u.vout) then result := result.push { txid := u.txid, vout := u.vout }', ["probes", "scope-dedup"], "PSBT probe request order/stopping"),
        ("last-value", source, 'outputs.filter (fun (key, _) => key != address)',
         'outputs.filter (fun (key, _) => key != address || key == address)', ["replay", "create-duplicate"], "PSBT full JSON/null/fee shape"),
        ("fee-distinct-count", source, 'Fee.estimateWeight inputs.size outputs.size', 'Fee.estimateWeight inputs.size (outputs.size + 1)', ["replay", "create-duplicate"], "PSBT full JSON/null/fee shape"),
        ("whole-sat", "Cyberkrill/Amounts.lean", 'if a.msat % 1000 != 0 then .error .wholeSatRequired else .ok a', 'if false then .error .wholeSatRequired else .ok a', ["refusals"], "PSBT output grammar/precedence"),
        ("fiat-precision-order", source, 'if let .inl value := value then let _ ← exactWholeSat value', 'if let .inl value := value then let _ := value', ["injected"], "PSBT fiat classification/precedence destination:1msat"),
        ("fiat-grouping", source, 'c == \',\' && !(index < protectedUntil)', 'c == \',\'', ["injected"], "PSBT quote failure has no client or child"),
        ("change-first-unused", source, '| .ok false => return .ok (some address)', '| .ok false => return .ok none', ["replay", "funded-unit"], "PSBT CLI success"),
        ("change-used", source, 'a.msat > 0', 'a.msat > 3000000000', ["replay", "funded-unit"], "PSBT CLI success"),
        ("change-bound", source, 'for index in [:200]', 'for index in [:199]', ["probes", "bound"], "PSBT probe request order/stopping"),
        ("change-failed-derivation", source, 'if let .ok address ← derive client indexed then',
         'if let .ok address ← derive client (if index == 0 then indexed else "disabled") then', ["probes", "failed-derivation"], "PSBT probe status"),
        ("received-fallback", source, 'return (← client.call "listunspent"', 'return (← client.call "disabled-listunspent"', ["probes", "fallback"], "PSBT probe status"),
        ("received-default", source, '| .ok _ => return .ok false', '| .ok _ => return .ok true', ["probes", "received-default"], "PSBT probe status"),
        ("fallback-default", source, '| .error _ => false)', '| .error _ => true)', ["probes", "list-default"], "PSBT probe status"),
        ("options-omission", core, 'if options.isEmpty then #[] else #[Json.mkObj options]', 'if false then #[] else #[Json.mkObj options]', ["synthetic", "defaults"], "PSBT synthetic defaults"),
        ("funded-zero-default", core, '| _ => pure (Amount.ofSats 0)', '| _ => pure (Amount.ofSats 1)', ["synthetic", "defaults"], "PSBT synthetic defaults/conversion"),
        ("funded-position-conversion", core, '(position + 2147483648) % 4294967296 - 2147483648', 'position', ["synthetic", "position-wrap"], "PSBT synthetic defaults/conversion"),
        ("retained-writer", app, 'prepareDecodeOutput services args.output | return .error .outputFailure\n    unless ListUtxos.networkValid args.network do',
         'prepareDecodeOutput services none | return .error .outputFailure\n    unless ListUtxos.networkValid args.network do', ["injected"], "PSBT retained single writer/raw before JSON"),
        ("raw-write", app, 'try services.writeOrdinaryFile path result.psbt catch _ => return .error .outputFailure',
         'try services.writeOrdinaryFile path (result.psbt ++ "\\n") catch _ => return .error .outputFailure', ["replay", "create-raw"], "PSBT raw bytes no newline"),
        ("expansion-size", source, 'let inputs ← match ← expand client args.inputs with',
         'let inputs ← match ← expand { client with maxResponseBytes := 1048576 } args.inputs with', ["limits", "funded-expansion-size"], "PSBT inherited funded-expansion-size"),
        ("probe-size", source, 'rpc (changeAddress client args.inputs)', 'rpc (changeAddress { client with maxResponseBytes := 1048576 } args.inputs)', ["limits", "funded-probe-size"], "PSBT inherited funded-probe-size"),
        ("final-size", source, 'client.walletCreateFundedPsbtCommand inputs outputs options',
         '({ client with maxResponseBytes := 1048576 } : CoreRpc.Client).walletCreateFundedPsbtCommand inputs outputs options', ["limits", "funded-final-size"], "PSBT inherited funded-final-size"),
    ]
    for check in ["curve", "hash", "same-point"]:
        rows.append(("full-validation-" + check, source, 'let _ ← PsbtCli.parse psbt',
                     'let _ := psbt', ["deep", check], "PSBT full validation " + check))
    rows += [
        ("funded-position-lexeme", core, 'if positionInteger body then value else', 'if true then value else', ["numeric", "exponent"], "PSBT numeric value exponent"),
        ("funded-whole-fee", source, 'let fee ← exactWholeSat result.fee', 'let fee ← pure result.fee', ["numeric", "msat-fee"], "PSBT numeric status msat-fee"),
        ("funded-fee-bound", source, 'unless fee.msat / 1000 ≤ 18446744073709551615 do', 'unless true do', ["numeric", "u64-fee-overflow"], "PSBT numeric status u64-fee-overflow"),
    ]
    rows += [
        ("rpc-original-spelling-create", source, 'unless (Base64.decode psbt).isSome do throw (.offline "psbtBase64")',
         'unless true do throw (.offline "psbtBase64")', ["spelling", "create-newline"], "PSBT original spelling rejection"),
        ("rpc-original-spelling-funded", source, 'unless (Base64.decode psbt).isSome do throw (.offline "psbtBase64")',
         'unless true do throw (.offline "psbtBase64")', ["spelling", "funded-newline"], "PSBT original spelling rejection"),
        ("fiat-indian-leading-three", "Cyberkrill/Fiat.lean", 'groups.length ≥ 3 && digits first && first.length ≤ 3',
         'groups.length ≥ 3 && digits first && first.length ≤ 2', ["injected"], "PSBT fiat classification/precedence destination:123,45,678INR"),
        ("fiat-finite-exponent", "Cyberkrill/Fiat.lean", 'let some amount := Exact.parse (number.replace "," "")',
         'let some amount := (if number.toLower.contains \'e\' then none else Exact.parse (number.replace "," ""))', ["injected"], "PSBT fiat classification/precedence destination:1e5USD"),
        ("fiat-before-precision", source, 'for (_, value) in parsed do',
         'if parsed.any (fun (_, value) => match value with | .inr _ => true | _ => false) then throw (.onchain "priceUnavailable:")\n  for (_, value) in parsed do', ["injected"], "PSBT fiat classification/precedence destination:1msat"),
        ("colon-core-boundary", source, "if outputs.any (fun (address, _) => address.contains ':') then return .error invalidOutput",
         "if false then return .error invalidOutput", ["boundaries", "colon"], "PSBT colon boundary refusal"),
        ("output-float-roundtrip", core, '.num ⟨Int.ofNat value.msat, if value.msat == 0 then 0 else 11⟩',
         '.num ⟨Int.ofNat value.msat.toUInt64.toFloat.toUInt64.toNat, 11⟩', ["exact", "create-wire"], "PSBT precise exact requests/stopping"),
    ]
    for command in ["funded", "create"]:
        for stage in (["expansion", "probe", "final"] if command == "funded" else ["expansion", "final"]):
            old, new = {
                "expansion": ('expand client args.inputs', 'expand { client with totalTimeoutMs := 30000 } args.inputs'),
                "probe": ('changeAddress client args.inputs', 'changeAddress { client with totalTimeoutMs := 30000 } args.inputs'),
                "final": ('client.walletCreateFundedPsbtCommand inputs outputs options', '({ client with totalTimeoutMs := 30000 } : CoreRpc.Client).walletCreateFundedPsbtCommand inputs outputs options') if command == "funded" else
                         ('client.createPsbt inputs outputs', '({ client with totalTimeoutMs := 30000 } : CoreRpc.Client).createPsbt inputs outputs'),
            }[stage]
            selection = command+"-"+stage+"-timeout"
            rows.append((selection, source, old, new, ["limits", selection], "PSBT inherited "+selection))
    for stage in ["expansion", "final"]:
        old, new = ('let inputs ← match ← expand client args.inputs with', 'let inputs ← match ← expand { client with maxResponseBytes := 1048576 } args.inputs with') if stage == "expansion" else (
            'client.createPsbt inputs outputs', '({ client with maxResponseBytes := 1048576 } : CoreRpc.Client).createPsbt inputs outputs')
        selection = "create-"+stage+"-size"
        rows.append((selection, source, old, new, ["limits", selection], "PSBT inherited "+selection))
    rows.append(("nonmultipath-probing", source, 'descriptorLike input && parts.length > 1',
                 'descriptorLike input', ["boundaries", "nonmultipath"], "PSBT nonmultipath descriptor no change probe/empty options omitted"))
    rows.append(("exact-output-submillisatoshi", source, 'let amount ← parseBitcoinOrFiat value',
                 'let amount ← parseBitcoinOrFiat (if value == "1000000.0004sat" then "1000000sat" else value)',
                 ["exact", "create-rounded"], "PSBT precise exact requests/stopping"))
    for name in ["negative", "tiny"]:
        rows.append(("exact-probe-"+name, source, '(CoreRpc.amount (.num n)).map (fun a => a.msat > 0)',
                     '.ok (n.toFloat > 0)', ["exact", "funded-"+name+"-probe"], "PSBT precise exact requests/stopping"))
    for command in ["create", "funded"]:
        for case in ["nbsp", "precedence", "unicode-separator"]:
            label = command+"-"+case
            rows.append(("fiat-suffix-"+label, source,
                         'drop unit.length |>.dropWhile Amount.rustWhitespace',
                         'drop unit.length |>.dropWhile asciiSpace', ["whitespace", label],
                         "PSBT scanner whitespace "+label))
        label = command+"-vertical-tab"
        rows.append(("fiat-ascii-"+label, source,
                     "[' ', '\\t', '\\r', '\\n', '\\x0c'].contains c",
                     "[' ', '\\t', '\\r', '\\n', '\\x0b', '\\x0c'].contains c",
                     ["whitespace", label], "PSBT scanner whitespace "+label))
        # Only the selected replay's owned fake HOME enables this forbidden lookup.
        rows.append(("implicit-cookie-"+command, core,
                     '  return pairAuth flags.user flags.password',
                     '  if flags.bitcoinDir.isNone && flags.user.isNone && flags.password.isNone then\n'
                     '    if let some home ← IO.getEnv "LCK_TEST_COOKIE_HOME" then\n'
                     '      if (← IO.getEnv "HOME") == some home then\n'
                     '        try\n'
                     '          if let some auth := parseCookie (← IO.FS.readFile (System.FilePath.mk home / ".bitcoin" / ".cookie")) then\n'
                     '            return some auth\n'
                     '        catch _ => pure ()\n'
                     '  return pairAuth flags.user flags.password',
                     ["boundaries", "auth-"+command+"-none"], "PSBT handler auth failure secret suppression"))
    return rows


def fingerprints():
    paths = ["Cyberkrill/Amounts.lean", "Cyberkrill/Fiat.lean", "Cyberkrill/App.lean", "Cyberkrill/CoreRpc.lean", "Cyberkrill/PsbtCommands.lean",
             "CyberkrillTests.lean", "CyberkrillTests/PsbtCommands.lean", "test/psbt-commands.py",
             "test/psbt-commands-mutations.py", "test/psbt-commands-provenance.json",
             "test/golden/psbt-commands-reference.json", "test/rpc-client.py"]
    return {p: hashlib.sha256((APP / p).read_bytes()).hexdigest() for p in paths}


def verify():
    record = json.loads(DEST.read_bytes())
    assert record["source_sha256"] == fingerprints(), "PSBT stale mutation evidence"
    rows = mutations()
    assert len(record["checks"]) == len(rows) == 57, "PSBT mutation selection inventory"
    for observed, (name, path, old, new, selection, assertion) in zip(record["checks"], rows):
        assert [observed[k] for k in ["property", "file", "replace", "with_text", "selection", "assertion"]] == [name, path, old, new, selection, assertion], "PSBT mutation identity"
        assert observed["build"]["status"] == observed["restore_build"]["status"] == observed["green"]["status"] == 0
        assert observed["red"]["status"] == 1 and assertion in observed["failure"], "PSBT genuine runtime red"
    assert record["initial_build"]["status"] == record["initial_green"]["status"] == record["restored_full"]["status"] == 0
    edits = len({(r[1], r[2], r[3]) for r in rows})
    assert edits == 44, "PSBT distinct production edit inventory"
    print(f"PSBT mutation evidence: {edits} distinct production edits / {len(rows)} named runtime reds; exact restoration; clean initial/restored builds", flush=True)


def main():
    if sys.argv[1:] == ["--verify"]: verify(); return 0
    assert not sys.argv[1:]
    LOGS.mkdir(parents=True, exist_ok=True)
    originals = {path: (APP / path).read_bytes() for _, path, *_ in mutations()}
    source = fingerprints()
    managed = [signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT]
    def cancelled(signum, _frame): raise InterruptedError("PSBT mutation interrupted")
    old_handlers = {sig: signal.signal(sig, cancelled) for sig in managed}
    def write(path, data):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try:
            (APP / path).write_bytes(data)
            assert (APP / path).read_bytes() == data, "PSBT exact source bytes"
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    def restore():
        for path, data in originals.items(): write(path, data)
    def command(name, args, expected, assertion=None):
        start = time.monotonic()
        with tempfile.TemporaryDirectory(prefix=name+"-", dir=LOGS) as temporary, chdir(APP):
            proc = run_owned(args, env=dict(os.environ, TMPDIR=temporary, PYTHONDONTWRITEBYTECODE="1"), capture_output=True, timeout=300)
        for stream in ["stdout", "stderr"]: (LOGS / (name+"."+stream)).write_bytes(getattr(proc, stream))
        (LOGS / (name+".status")).write_text(str(proc.returncode)+"\n")
        data = dict(command=args, status=proc.returncode, seconds=round(time.monotonic()-start, 3))
        assert proc.returncode == expected, "PSBT mutation command " + name
        failure = (proc.stdout+proc.stderr).decode(errors="replace")
        if assertion: assert assertion in failure and "assertion" in failure.lower(), "PSBT intended runtime assertion " + name
        return data
    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    tests = ["python3", "-B", "test/psbt-commands.py"]
    try:
        initial_build = command("initial-build", build, 0)
        initial_green = command("initial-green", tests, 0)
        checks = []
        for i, (name, path, old, new, selected, assertion) in enumerate(mutations()):
            text = originals[path].decode()
            # The first matching decoder writer belongs to the new handler;
            # the independent existing list handler retains the same pattern.
            expected_matches = 2 if name == "retained-writer" else 1
            assert text.count(old) == expected_matches, "PSBT mutation match count " + name
            label = f"{i:02}-{name}"
            try:
                write(path, text.replace(old, new, 1).encode())
                compiled = command(label+"-build", build, 0)
                red = command(label+"-red", tests+selected, 1, assertion)
            finally: restore()
            rebuilt = command(label+"-restore-build", build, 0)
            green = command(label+"-green", tests+selected, 0)
            checks.append(dict(property=name, file=path, replace=old, with_text=new, selection=selected,
                               assertion=assertion, failure=next(line for line in (LOGS / (label+"-red.stderr")).read_text().splitlines()
                                            if line.startswith("AssertionError:") and assertion in line),
                               build=compiled, red=red, restore_build=rebuilt, green=green))
            print(name+": build/red/restore/green 0/1/0/0", flush=True)
        full = command("restored-full", tests, 0)
        assert source == fingerprints(), "PSBT final source restoration"
        write_record(DEST, json.dumps(dict(source_sha256=source, checks=checks, initial_build=initial_build, initial_green=initial_green, restored_full=full), indent=2) + '\n')
        verify()
    finally:
        restore()
        for sig, handler in old_handlers.items(): signal.signal(sig, handler)
    return 0


if __name__ == "__main__": sys.exit(main())
