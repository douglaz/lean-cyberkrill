#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compiled production mutations; named runtime failures, exact restoration and greens."""
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

from evidence_history import publish_history
from cases import APP
from network import run_owned

DEST = APP / "test/golden/list-utxos-mutation-record.json"
LOGS = APP / ".lake/validation/list-utxos-mutations" / str(time.time_ns())
PREVIOUS_SHA256 = "d0b4914d0a123e5a85dc6d53a732d71712ca18b41f07e27f78a0c2445dcc917a"
SCHEMA_SHA256 = "c8935d83811d4535fbb9fd0c70bb51ba0c5b1e07fbdec8e384c79304da98ef65"
CANCELLED = None


def remember_cancellation(signum):
    global CANCELLED
    if CANCELLED is None: CANCELLED = signum
    return 128 + CANCELLED


def edits():
    reader = "Cyberkrill/Frozenkrill.lean"
    app = "Cyberkrill/App.lean"
    listing = "Cyberkrill/ListUtxos.lean"
    rpc = "Cyberkrill/CoreRpc.lean"
    schema = ["schema"]
    injected = ["injected"]
    replay = ["replay", "descriptor-1-9999999"]
    rows = [
        ("wallet-marker", reader, '(← string j "wallet") == "frozenkrill"', '(← string j "wallet") != "other"', schema, "wallet schema wallet marker"),
        ("version-required", reader, 'let _ ← u32 (← required j "version")', 'pure ()', schema, "wallet schema required missing version"),
        ("unused-field-required", reader, 'for key in ["master_fingerprint", "singlesig_xpub"', 'for key in ["singlesig_xpub"', schema, "wallet schema required missing master_fingerprint"),
        ("u32-bound", reader, 'n ≤ 4294967295 then', 'true then', schema, "wallet schema u32 bounds"),
        ("sigtype-case", reader, 'let value := value.toLower', 'let value := value', schema, "wallet schema sigtype case"),
        ("sigtype-first-match", reader, '0 < m && m ≤ n', '0 ≤ m && m ≤ n', schema, "wallet schema multisig rejection"),
        ("sigtype-maximum", reader, 'n ≤ 15 do', 'n ≤ 16 do', schema, "wallet schema multisig rejection"),
        ("address-metadata", reader, 'optional item "index" u32', 'pure ()', schema, "wallet schema address u32 lexical type"),
        ("u32-lexical-type", reader, 'Json.parse (String.ofList (schemaNumbers text.toList))', 'Json.parse text', schema, "wallet schema u32 lexical type"),
        ("u32-negative-zero", reader, 'token == "-0".toList ||', 'false ||', schema, "wallet schema u32 lexical type"),
        ("duplicate-detector", reader, 'checkObject root known', 'checkObject root (known.filter (fun key => !["wallet", "version", "sigtype"].contains key))', ["lexical", "duplicate-detector"], "wallet lexical duplicate-detector"),
        ("duplicate-schema", reader, 'checkObject root known', 'checkObject root ["wallet", "version", "sigtype"]', ["lexical", "duplicate-schema"], "wallet lexical duplicate-schema"),
        ("duplicate-address", reader, 'checkObject item ["address", "derivation_path", "index"]', 'checkObject item []', ["lexical", "duplicate-address"], "wallet lexical duplicate-address"),
        ("string-root", reader, 'unless valid do throw "string escape"', 'unless valid || known.contains "wallet" do throw "string escape"', ["lexical", "string-root"], "wallet lexical string-root"),
        ("string-address", reader, 'unless valid do throw "string escape"', 'unless valid || known.contains "address" do throw "string escape"', ["lexical", "string-address"], "wallet lexical string-address"),
        ("string-key", reader, 'unless validKeys do throw "field escape"', 'unless true do throw "field escape"', ["lexical", "string-key"], "wallet lexical string-key"),
        ("dispatch", app, '| .listUtxos args => do', '| .listUtxos args => do\n    if true then return .error .invalidArguments', injected, "list dispatch"),
        ("source-conflict", app, 'if sources.length > 1 then throw .invalidArguments', 'if false then throw .invalidArguments', ["failures"], "list named error invalidArguments"),
        ("help-source-precedence", app, 'if p.hasFlag "help" || args.isEmpty then', 'if (p.hasFlag "help" && (["descriptor", "addresses", "wallet-file"].filter p.hasFlag).length ≤ 1) || args.isEmpty then', ["help", "source"], "list help conflict source"),
        ("help-credential-precedence", app, 'if p.hasFlag "help" || args.isEmpty then', 'if (p.hasFlag "help" && !(p.hasFlag "bitcoin-dir" && (p.hasFlag "rpc-user" || p.hasFlag "rpc-password"))) || args.isEmpty then', ["help", "credential"], "list help conflict credential"),
        ("typed-before-help", app, 'validateTypedArgs (args.head?.getD "") args.tail', 'pure ()', ["help", "typed"], "list help typed ordering"),
        ("help-before-typed", app, 'let args := throughHelp args', 'validateTypedArgs (args.head?.getD "") args.tail\n  let args := throughHelp args', ["help", "typed"], "list help typed ordering"),
        ("confirmation-u32", app, 'unless (wordCount? flag).isSome do', 'unless true do', injected, "list u32 rejected before help"),
        ("writer-once", app, '| .listUtxos args => do\n    let .ok writer ← prepareDecodeOutput services args.output', '| .listUtxos args => do\n    let _ ← prepareDecodeOutput services args.output\n    let .ok writer ← prepareDecodeOutput services args.output', injected, "list retained single writer"),
        ("writer-before-network", app, '| .listUtxos args => do\n    let .ok writer ← prepareDecodeOutput services args.output', '| .listUtxos args => do\n    if !ListUtxos.networkValid args.network then return .error (.onchain "invalidNetwork: Expected network")\n    let .ok writer ← prepareDecodeOutput services args.output', injected, "list writer before invalidNetwork"),
        ("address-order", listing, ')).toArray', ')).reverse.toArray', ["replay", "addresses"], "list CLI success addresses"),
        ("shape-desc-null", listing, 'optionalString u.raw "descriptor"', 'optionalString u.raw "desc"', replay, "list exact shape/nulls/order/filter/totals"),
        ("amount-exact", listing, '("amount_sats", toJson sats)', '("amount_sats", toJson (sats + 1))', replay, "list exact shape/nulls/order/filter/totals"),
        ("binary64-precision", listing, 'let sats := u.amount.msat / 1000', 'let sats := (u.amount.msat / 1000).toFloat.toUInt64.toNat', ["synthetic", "precision"], "list exact amount above binary64 integer precision"),
        ("total-exact", listing, 'total := total + value.amount.msat / 1000', 'total := total + value.amount.msat / 1000 + 1', replay, "list exact shape/nulls/order/filter/totals"),
        ("count", listing, '("total_count", toJson outputs.size)', '("total_count", toJson (outputs.size + 1))', replay, "list exact shape/nulls/order/filter/totals"),
        ("inclusive-lower", listing, 'lo ≤ conf && conf ≤ hi', 'lo < conf && conf ≤ hi', replay, "list exact shape/nulls/order/filter/totals"),
        ("inclusive-upper", listing, 'lo ≤ conf && conf ≤ hi', 'lo ≤ conf && conf < hi', ["replay", "descriptor-1-1"], "list exact shape/nulls/order/filter/totals"),
        ("empty-filter", listing, 'bounds.all (fun (lo, hi) => lo ≤ conf && conf ≤ hi)', 'true', ["replay", "descriptor-3-9999999"], "list exact shape/nulls/order/filter/totals"),
        ("wallet-order", listing, 'receiving ++ change', 'change ++ receiving', ["replay", "single-1-9999999"], "list exact shape/nulls/order/filter/totals"),
        ("cross-half-dedup", listing, 'receiving ++ change', '(receiving ++ change).foldl (fun acc u => if acc.any (fun v => v.txid == u.txid && v.vout == u.vout) then acc else acc.push u) (#[] : Array CoreRpc.Utxo)', ["wallet-halves"], "list no cross-half dedup/order"),
        ("per-descriptor-dedup", rpc, 'unless result.any (fun u => u.txid == value.txid && u.vout == value.vout) do', 'if true then', ["synthetic", "dedup"], "list descriptor first-seen dedup"),
        ("derive-failure-continuation", rpc, '| .error _ => pure #[]', '| .error e => return .error e', ["synthetic", "derive-failure"], "list composed success derive-failure"),
        ("ignored-import", rpc, 'let _ ← client.importDescriptors #[info.descriptor]', 'let .ok _ ← client.importDescriptors #[info.descriptor] | return .error .invalidResult', ["synthetic", "import-failure"], "list composed success import-failure"),
        ("address-confirmation-parameters", listing, 'client.listUnspent args.minConf args.maxConf', 'client.listUnspent 0 9999999', ["address-controls"], "list address bounds/default/empty request"),
        ("derive-range", rpc, 'info.descriptor (some (0, 99))', 'info.descriptor (some (0, 98))', replay, "list CLI success descriptor-1-9999999"),
        ("client-size-inheritance", listing, 'let values ← match args.descriptor', 'let client := { client with maxResponseBytes := 1048576 }\n  let values ← match args.descriptor', ["synthetic", "size-large"], "list composed success size-large"),
        ("client-timeout-inheritance", listing, 'let values ← match args.descriptor', 'let client := { client with totalTimeoutMs := 30000 }\n  let values ← match args.descriptor', ["synthetic", "timeout"], "list inherited limit timeout"),
    ]
    split_guard = '''else if ["--descriptor", "--addresses", "--wallet-file", "--rpc-url", "--bitcoin-dir",
        "--rpc-user", "--rpc-password", "--inputs", "--outputs", "--psbt-output", "--estimate-mode"].contains flag then
      (!(value.startsWith "-") || value == "-") && outputArgsValid valueFlags rest'''
    rows += [
        ("split-refusal", app, split_guard, split_guard.replace('(!(value.startsWith "-") || value == "-") && ', ''), ["split"], "list split refusal side effects"),
        ("split-attached", app, 'let sources := ["descriptor", "addresses", "wallet-file"].filter p.hasFlag',
         'if (flag "descriptor").any (·.startsWith "-") then throw .invalidArguments\n    let sources := ["descriptor", "addresses", "wallet-file"].filter p.hasFlag', ["split"], "list attached value acceptance"),
        ("split-literal-dash", app, split_guard, split_guard.replace(' || value == "-"', ''), ["split"], "list split dash/empty acceptance"),
        ("split-empty", app, split_guard, split_guard.replace('&& outputArgsValid valueFlags rest', '&& !value.isEmpty && outputArgsValid valueFlags rest'), ["split"], "list split dash/empty acceptance"),
        ("attached-value-bytes", app, 'rpc, descriptor := flag "descriptor",', 'rpc, descriptor := (flag "descriptor").map (fun value => (value.splitOn "=").head!),', ["split"], "list attached value bytes"),
        ("positional-acceptance", reader, '| .arr values => do\n        unless', '| .arr values => do\n        if true then throw "sequence refused"\n        unless', ["positional", "acceptance"], "wallet positional acceptance"),
        ("positional-short-arity", reader, 'values.size == 3', 'values.size ≤ 3', ["positional", "arity-short"], "wallet positional arity-short"),
        ("positional-long-arity", reader, 'values.size == 3', '3 ≤ values.size', ["positional", "arity-long"], "wallet positional arity-long"),
        ("positional-address-type", reader, '("address", values[0]?.getD .null)', '("address", .str "synthetic")', ["positional", "address-type"], "wallet positional address-type"),
        ("positional-path-type", reader, '("derivation_path", values[1]?.getD .null)', '("derivation_path", .null)', ["positional", "path-type"], "wallet positional path-type"),
        ("positional-index-type", reader, '("index", values[2]?.getD .null)', '("index", .null)', ["positional", "index-type"], "wallet positional index-type"),
        ("positional-address-escape", reader, 'for slot in slots do', 'for slot in slots.drop 1 do', ["positional", "address-escape"], "wallet positional address-escape"),
        ("positional-path-escape", reader, 'for slot in slots do', 'for slot in slots.take 1 do', ["positional", "path-escape"], "wallet positional path-escape"),
        ("positional-valid-unicode", reader, 'unless valid do throw "slot escape"', 'unless false do throw "slot escape"', ["positional", "unicode"], "wallet positional unicode"),
        ("positional-index-bound", reader, 'n ≤ 4294967295 then', 'true then', ["positional", "index-type"], "wallet positional index-type"),
        ("positional-index-lexical", reader, 'Json.parse (String.ofList (schemaNumbers text.toList))', 'Json.parse text', ["positional", "index-type"], "wallet positional index-type"),
    ]
    for name, action in [("output", 'services.openOrdinaryFile "unused"'),
                         ("read", 'services.readFile "unused"'),
                         ("client", 'services.coreClient {}'),
                         ("rpc", 'services.listUtxos { url := "unused" } {} none')]:
        rows.append(("split-refusal-" + name, app, '| .error e => return ← reportError services e',
                     '| .error e =>\n      let _ ← ' + action + '\n      return ← reportError services e',
                     ["split"], "list split refusal side effects"))
    assert len(rows) == 63
    return rows


def fingerprints():
    paths = ["Cyberkrill/App.lean", "Cyberkrill/Amounts.lean", "Cyberkrill/Frozenkrill.lean", "Cyberkrill/ListUtxos.lean", "Cyberkrill/CoreRpc.lean", "Cyberkrill/RpcFlags.lean",
             "CyberkrillTests/ListUtxos.lean", "CyberkrillTests.lean", "test/list-utxos.py", "test/list-utxos-mutations.py", "test/list-utxos-lifecycle.py", "test/network.py", "test/list-utxos-provenance.json", "test/golden/list-utxos-reference.json"]
    return {p: hashlib.sha256((APP / p).read_bytes()).hexdigest() for p in paths}


def command(label, args, status, assertion=None):
    terminal = 1
    try:
        with tempfile.TemporaryDirectory(prefix=label + "-tmp-", dir=LOGS) as temporary, chdir(APP):
            environment = dict(os.environ, TMPDIR=temporary, PYTHONDONTWRITEBYTECODE="1")
            # Redirect in the child so interrupted commands retain even empty
            # streams. run_owned finishes descendant cleanup before unwinding
            # to either driver's source-restoration/recovery paths.
            proc = run_owned(
                ["bash", "--noprofile", "--norc", "-c",
                 'out=$1; err=$2; shift 2; exec "$@" >"$out" 2>"$err"', "list-mutation",
                 str(LOGS / (label + ".stdout")), str(LOGS / (label + ".stderr")),
                 "timeout", "--foreground", "180", *args],
                env=environment, timeout=190, gate_cancellation=True, on_cancel=remember_cancellation)
            terminal = proc.returncode
    except SystemExit as error:
        terminal = error.code
        raise
    except subprocess.TimeoutExpired:
        terminal = 124
        raise
    finally:
        # Defer late signals through both the decision and the complete write.
        # Unmask only after the record exists; restored handlers still propagate
        # the saved first cancellation. Other errors retain their own status.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                      [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM])
        try:
            if isinstance(sys.exception(), SystemExit) and CANCELLED is not None:
                terminal = 128 + CANCELLED
            (LOGS / (label + ".status")).write_text(str(terminal) + "\n")
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    streams = {s: (LOGS / (label + "." + s)).read_text() for s in ["stdout", "stderr"]}
    assert proc.returncode == status, f"list mutation {label}: expected {status}, got {proc.returncode}: {streams}"
    if assertion:
        assert assertion in streams["stderr"] and ("AssertionError:" in streams["stderr"] or "assertion failed:" in streams["stderr"]), "list runtime detecting assertion " + label + ": " + str(streams)
    # Paths in diagnostics are machine framing. Store exact streams privately;
    # public evidence retains their independent digests and the named assertion.
    return dict(command=args, status=proc.returncode,
                stdout_sha256=hashlib.sha256(streams["stdout"].encode()).hexdigest(),
                stderr_sha256=hashlib.sha256(streams["stderr"].encode()).hexdigest())


PRE_PSBT_SHA256 = '9f629d18f9069aa28d941ee616259a466f95a6d1d87b69f92699f8dd441a3837'

def verify():
    record = json.loads(DEST.read_bytes())
    retained = record["pre_psbt_observation"]
    assert hashlib.sha256((json.dumps(retained, indent=2) + "\n").encode()).hexdigest() == PRE_PSBT_SHA256, "retained pre-PSBT observation"
    previous = record["previous_observation"]
    assert previous["count"] == 33 and hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == PREVIOUS_SHA256, "retained 33-edit list observation"
    schema = record["schema_observation"]
    assert schema["count"] == 43 and hashlib.sha256((json.dumps(schema, indent=2) + "\n").encode()).hexdigest() == SCHEMA_SHA256, "retained 43-edit schema observation"
    assert record["source_sha256"] == fingerprints(), "stale list mutation evidence"
    assert record["count"] == len(record["checks"]) == len(edits()) == 63, "list mutation inventory"
    for row, (name, path, old, new, selected, assertion) in zip(record["checks"], edits()):
        assert (row["property"], row["file"], row["replace"], row["with_text"], row["assertion"]) == (name, path, old, new, assertion)
        assert [row[k]["status"] for k in ["build", "red", "restore_build", "green"]] == [0, 1, 0, 0]
    assert record["baseline"]["status"] == record["restored_full"]["status"] == 0
    print("list mutation evidence: 63 compiled edits; 63 named runtime reds; 63 restored greens; prior 33/43 observations retained")


def main():
    global CANCELLED
    if sys.argv[1:] == ["--verify"]: verify(); return 0
    assert sys.argv[1:] == []
    CANCELLED = None
    LOGS.mkdir(parents=True, exist_ok=True)
    hashes = fingerprints()
    prior = json.loads(DEST.read_bytes())
    pre_psbt = prior.get("pre_psbt_observation", {k: v for k, v in prior.items() if not k.endswith("_observation")})
    assert hashlib.sha256((json.dumps(pre_psbt, indent=2) + "\n").encode()).hexdigest() == PRE_PSBT_SHA256, "original pre-PSBT observation"
    schema = prior.get("schema_observation", prior)
    assert hashlib.sha256((json.dumps(schema, indent=2) + "\n").encode()).hexdigest() == SCHEMA_SHA256
    previous = prior.get("previous_observation", prior)
    assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == PREVIOUS_SHA256
    originals = {APP / p: (APP / p).read_bytes() for _, p, *_ in edits()}
    managed = [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]
    def restore():
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try:
            for path, data in originals.items(): path.write_bytes(data); assert path.read_bytes() == data
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    # Never restore in a signal handler: an active command must first unwind
    # through its descendant cleanup, then the driver's finally restores.
    def interrupted(signum, _frame): raise SystemExit(remember_cancellation(signum))
    handlers = {sig: signal.signal(sig, interrupted) for sig in managed}
    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    records = []
    try:
        baseline = command("baseline", build, 0)
        for i, (name, relative, old, new, selected, assertion) in enumerate(edits()):
            path = APP / relative; source = originals[path].decode()
            assert source.count(old) == 1, "unique list mutation " + name
            label = f"{i:02}-{name}"
            try:
                path.write_text(source.replace(old, new, 1))
                assert path.read_text() == source.replace(old, new, 1)
                compiled = command(label + "-build", build, 0)
                red = command(label + "-red", ["python3", "-B", "test/list-utxos.py", *selected], 1, assertion)
            finally: restore()
            rebuilt = command(label + "-restore-build", build, 0)
            green = command(label + "-green", ["python3", "-B", "test/list-utxos.py", *selected], 0)
            records.append(dict(property=name, file=relative, replace=old, with_text=new, assertion=assertion,
                                build=compiled, red=red, restore_build=rebuilt, green=green))
            (LOGS / "progress.json").write_text(json.dumps(dict(source_sha256=hashes, checks=records), indent=2) + "\n")
            print(name + ": build/red/restore/green 0/1/0/0", flush=True)
        full = command("restored-full", ["python3", "-B", "test/list-utxos.py"], 0)
        assert fingerprints() == hashes, "list exact final restoration"
        publish_history(DEST, json.dumps(dict(pre_psbt_observation=pre_psbt, count=len(records), source_sha256=hashes, baseline=baseline, checks=records, restored_full=full, previous_observation=previous, schema_observation=schema), indent=2) + "\n")
        verify()
    except SystemExit:
        # Cancellation is terminal. Cleanup has reaped the command; restore
        # bytes here, and let the next invocation build before any mutation.
        restore(); raise
    except BaseException:
        restore()
        command("failure-restore-build", build, 0)
        raise
    finally:
        restore()
        for sig, handler in handlers.items(): signal.signal(sig, handler)
    return 0


if __name__ == "__main__": sys.exit(main())
