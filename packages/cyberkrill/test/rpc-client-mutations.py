#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compiled client regressions and independently selected sentinel safety regressions."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import types

from cases import APP
import network

S = importlib.import_module("network-safety")
SOURCE = APP / "Cyberkrill/CoreRpc.lean"
FLAGS = APP / "Cyberkrill/RpcFlags.lean"
DEST = APP / "test/golden/rpc-client-mutation-record.json"
LOGS = APP / ".lake/validation/rpc-client-mutations-round2"
PREVIOUS_SHA256 = "ceacb68cf44ee76be24595af3f33022898a03040f2e4e6a4b1053c1fb050d693"


def client_edits():
    pure = [".lake/build/bin/CyberkrillTests", "--rpc-pure"]
    replay = ["python3", "-B", "test/rpc-client.py", "replay"]
    auth = ["python3", "-B", "test/rpc-client.py", "auth"]
    synthetic = ["python3", "-B", "test/rpc-client.py", "synthetic"]
    precision = ["python3", "-B", "test/rpc-client.py", "precision"]
    rows = [
        ("credential-pair", SOURCE, 'return (← user, ← password)', 'return (user.getD "lck", password.getD "lck-throwaway")', pure, "RPC both credentials present"),
        ("cookie-trim", SOURCE, 'cookie.toList.dropWhile cookieSpace', 'cookie.toList', pure, "RPC cookie trim/first colon"),
        ("cookie-unicode-space", SOURCE, 'cookie.toList.dropWhile cookieSpace', 'cookie.toList.dropWhile (fun c => c.toNat < 128 && cookieSpace c)', pure, "RPC cookie trim/first colon"),
        ("cookie-first-colon", SOURCE, 'String.intercalate ":" (password :: rest)', 'String.intercalate ":" (rest ++ [password])', pure, "RPC cookie trim/first colon"),
        ("cookie-preference", SOURCE, 'return some auth', 'return pairAuth flags.user flags.password', auth, "RPC auth resolution cookie"),
        ("empty-cookie-directory", SOURCE, 'if directory.isEmpty then System.FilePath.mk ".cookie"',
         'if false then System.FilePath.mk ".cookie"', ["python3", "-B", "test/rpc-client.py", "auth/empty-directory"],
         "RPC empty directory relative cookie path"),
        ("cookie-fallback", SOURCE, 'catch _ => pure ()\n  return pairAuth', 'catch _ => return none\n  return pairAuth', auth, "RPC auth resolution missing-fallback"),
        ("malformed-cookie-fallback", SOURCE, 'if let some auth := parseCookie', 'if let some auth := (fun s => (parseCookie s).orElse (fun _ => some ("wrong", "wrong")))', auth, "RPC auth resolution malformed-fallback"),
        ("auth-transport", SOURCE, 'basicAuth := client.auth', 'basicAuth := none', replay, "RPC getdescriptorinfo success"),
        ("negative-amount", SOURCE, 'let some a := Amount.ofJsonNumber n', 'let some a := Amount.ofJsonNumber ⟨Int.ofNat n.mantissa.natAbs, n.exponent⟩', pure, "RPC exact incoming precision -1"),
        ("sub-msat", SOURCE, 'let some a := Amount.ofJsonNumber n', 'let some a := (Amount.ofJsonNumber n).orElse (fun _ => if n.mantissa < 0 then none else some ⟨n.mantissa.toNat * 10^11 / 10^n.exponent⟩)', pure, "RPC exact incoming precision 1e-12"),
        ("binary64-integer", SOURCE, 'let some a := Amount.ofJsonNumber n', 'let some a := Amount.ofJsonNumber ⟨if n.exponent == 0 then Int.ofNat n.mantissa.toNat.toFloat.toUInt64.toNat else n.mantissa, n.exponent⟩', pure, "RPC exact incoming precision 9007199254740993"),
        ("incoming-exponent", SOURCE, 'let some a := Amount.ofJsonNumber n', 'let some a := Amount.ofJsonNumber ⟨n.mantissa, n.exponent + 1⟩', precision, "RPC HTTP incoming exact precision"),
        ("outgoing-number", SOURCE, '.num ⟨Int.ofNat value.msat, if value.msat == 0 then 0 else 11⟩', '.str (toString value.msat)', pure, "RPC exact outgoing precision/type"),
        ("outgoing-scale", SOURCE, 'if value.msat == 0 then 0 else 11', 'if value.msat == 0 then 0 else 10', precision, "RPC HTTP outgoing numeric precision"),
        ("generic-zero", SOURCE, '(wireJson body).compress.toUTF8', 'body.compress.toUTF8', precision, "RPC generic exact zero serialization"),
        ("http-before-json", SOURCE, 'unless response.status >= 200 && response.status < 300 do throw (.http response.status)', 'pure ()', synthetic, "RPC synthetic http-before-json"),
        ("rpc-error", SOURCE, 'unless error == .null do throw (.rpc (error.getObjValAs? Int "code").toOption)', 'pure ()', synthetic, "RPC synthetic rpc"),
        ("result-null", SOURCE, 'value.getObjVal? "result" |>.mapError', '(value.getObjVal? "result" >>= fun j => if j == .null then .error "absent" else .ok j) |>.mapError', synthetic, "RPC synthetic null-result"),
        ("optional-error-member", SOURCE, 'if let .ok error := value.getObjVal? "error" then', 'let error ← (value.getObjVal? "error").mapError (fun _ => Error.malformed)\n  if true then', synthetic, "RPC synthetic omitted-error"),
        ("missing-result", SOURCE, 'value.getObjVal? "result" |>.mapError (fun _ => Error.missingResult)', 'pure ((value.getObjVal? "result").toOption.getD .null)', synthetic, "RPC synthetic missing"),
        ("request-verb", SOURCE, 'method := .post, url := client.url', 'method := .get, url := client.url', replay, "RPC getdescriptorinfo success"),
        ("request-version", SOURCE, '("jsonrpc", .str "2.0")', '("jsonrpc", .str "1.0")', replay, "RPC version/id"),
        ("request-id", SOURCE, '("id", .str "cyberkrill")', '("id", .str "wrong")', replay, "RPC version/id"),
        ("scoped-flag-conflict-user", FLAGS, '(user.isSome || password.isSome)', 'password.isSome', pure, "RPC directory conflicts with either credential"),
        ("scoped-flag-conflict-password", FLAGS, '(user.isSome || password.isSome)', 'user.isSome', pure, "RPC directory conflicts with either credential"),
        ("flag-url-default", FLAGS, 'url : String := "http://127.0.0.1:8332"', 'url : String := "http://127.0.0.1:18444"', pure, "RPC default URL and absent credentials"),
        ("import-continuation", SOURCE, 'let _ ← client.importDescriptors #[info.descriptor]', 'let result ← client.importDescriptors #[info.descriptor]\n    if result.toOption.isSome then return .error .invalidResult', ["python3", "-B", "test/rpc-client.py", "continuation"], "RPC ignored import continuation"),
        ("descriptor-helper-error", SOURCE, 'let info ← match ← client.getDescriptorInfo desc with\n      | .error e => return .error e',
         'let info ← match ← client.getDescriptorInfo desc with\n      | .error _ => return .error .invalidResult',
         ["python3", "-B", "test/rpc-client.py", "continuation_failure"], "RPC descriptor helper HTTP 401"),
        ("capture-spawn-integration", APP / "test/generate-rpc-recordings.py", '        refuse_spawn(args[1:], stub_url)', '        pass',
         ["python3", "-B", "test/network-safety.py", "--spawn", "onchain-list-utxos/absent"], "capture sentinel did not start: onchain-list-utxos/absent"),
        ("capture-alternate-basename", APP / "test/generate-rpc-recordings.py", '    if reference:',
         '    if reference and Path(args[0]).name == "cyberkrill":',
         ["python3", "-B", "test/network-safety.py", "--spawn", "dca"], "capture sentinel did not start: dca/reference-copy"),
    ]
    # Each request builder is disabled separately; all eleven must reach the responder.
    for method, assertion in [
        ("listunspent", "RPC listunspent success"), ("scantxoutset", "RPC scantxoutset success"),
        ("getdescriptorinfo", "RPC getdescriptorinfo success"), ("deriveaddresses", "RPC deriveaddresses success"),
        ("createpsbt", "RPC createpsbt success"), ("walletcreatefundedpsbt", "RPC walletcreatefundedpsbt success"),
        ("importdescriptors", "RPC importdescriptors response"), ("getblockchaininfo", "RPC getblockchaininfo success"),
        ("getreceivedbyaddress", "RPC getreceivedbyaddress success"), ("getrawtransaction", "RPC getrawtransaction success"),
        ("getblock", "RPC getblock success")]:
        rows.append(("wrapper-" + method, SOURCE, 'client.call "' + method + '"', 'client.call "disabled-' + method + '"', replay, assertion))
    rows += [
        ("list-filter", SOURCE, 'toJson minConf, toJson maxConf', 'toJson (minConf + 1), toJson maxConf', replay, "RPC listunspent success"),
        ("derive-range", SOURCE, 'fun (lo, hi) => #[toJson #[lo, hi]]', 'fun (lo, hi) => #[toJson #[lo, hi + 1]]', replay, "RPC deriveaddresses success"),
        ("scan-range", SOURCE, '[("range", toJson #[lo, hi])]', '[("range", toJson #[lo, hi + 1])]', replay, "RPC scantxoutset success"),
        ("input-order", SOURCE, '.arr (inputs.map (·.json)), outputsJson outputs,\n', '.arr (inputs.reverse.map (·.json)), outputsJson outputs,\n', replay, "RPC createpsbt success"),
        ("funded-options", SOURCE, 'toJson locktime.toNat, options]', 'toJson locktime.toNat, .null]', replay, "RPC walletcreatefundedpsbt success"),
        ("import-now", SOURCE, '("timestamp", .str "now")', '("timestamp", toJson (0 : Nat))', replay, "RPC importdescriptors response"),
        ("import-range", SOURCE, '("range", toJson #[0, 1000])', '("range", toJson #[0, 999])', replay, "RPC importdescriptors response"),
        ("received-confirmations", SOURCE, '#[.str address, toJson minConf]', '#[.str address, toJson (minConf + 1)]', replay, "RPC getreceivedbyaddress success"),
        ("transaction-verbosity", SOURCE, '#[.str txid, .bool true]', '#[.str txid, .bool false]', replay, "RPC getrawtransaction success"),
        ("utxo-conversion", SOURCE, 'amount := ← amount (← field raw "amount")', 'amount := Amount.ofMsat 0', replay, "RPC UTXO exact amount"),
        ("scan-total", SOURCE, 'total := ← amount (← field raw "total_amount")', 'total := Amount.ofMsat 0', replay, "RPC scan exact total"),
        ("funded-fee", SOURCE, 'fee := ← amount (← field raw "fee")', 'fee := Amount.ofMsat 0', replay, "RPC funded exact fee"),
        ("transaction-value", SOURCE, 'do amount (← field output "value")', 'do let _ := output; pure (Amount.ofMsat 0)', replay, "RPC transaction exact value"),
    ]
    for case in ["unreadable-fallback", "malformed-no-pair", "unreadable-no-pair", "missing-no-pair"]:
        old = 'return pairAuth flags.user flags.password'
        # Keep the successful cookie path untouched; change fallback alone.
        rows.append(("auth-fallback-" + case, SOURCE, old, 'return some ("lck", "lck-throwaway")' if case.endswith("no-pair") else 'return none',
                     ["python3", "-B", "test/rpc-client.py", "auth/" + case], "RPC recorded 401 " + case if case.endswith("no-pair") else "RPC auth resolution " + case))
    # Store untrusted material in a diagnostic only in the changed source. The
    # fixed test checks each distinct secret sentinel before envelope semantics.
    prefix = SOURCE.read_text().split('def Client.call', 1)[0]
    for name, target in [
        ("malformed", '(Json.parse body).mapError (fun _ => Error.malformed)'),
        ("rpc", 'throw (.rpc (error.getObjValAs? Int "code").toOption)'),
        ("http-before-json", 'throw (.http response.status)')]:
        replacement = prefix.replace('  | transport\n', '  | transport\n  | leak (text : String)\n', 1)
        replacement = replacement.replace('  | .transport =>', '  | .leak text => text\n  | .transport =>', 1)
        if name == "malformed": replacement = replacement.replace(target, '(Json.parse body).mapError (fun _ => Error.leak body)', 1)
        elif name == "rpc": replacement = replacement.replace(target, 'throw (.leak body)', 1)
        else: replacement = replacement.replace(target, 'throw (.leak ((String.fromUTF8? response.body).getD ""))', 1)
        rows.append(("secret-" + name, SOURCE, prefix, replacement, synthetic, "RPC secret suppression " + name))
    assert len(rows) == 62, "client mutation inventory"
    return rows


def network_edits():
    source = Path(network.__file__)
    # Each selected refusal has its own sentinel invocation, so the first refusal
    # cannot hide loss of a later position, spelling or command boundary.
    rows = [("spawn/" + name, source, '    refuse_spawn(args, stub_url)\n    return subprocess.run',
             '    pass\n    return subprocess.run', "spawn", name, "spawn sentinel did not start: " + name)
            for name, _ in S.spawn_cases()]
    for name in ["missing", "refused", "marker", "inherited-inode"]:
        rows.append(("namespace/" + name, source, 'if sandbox() or isolated():', 'if True:', "namespace", name,
                     "namespace sentinel did not start: " + name))
    rows.append(("namespace/loopback", source, 'ip link set lo up || exit 125;', 'ip link set lo up;',
                 "namespace", "loopback", "namespace status: loopback"))
    rows.append(("namespace/test-failure", source, 'return run_owned(command, timeout=timeout).returncode',
                 'run_owned(command, timeout=timeout)\n        return 0',
                 "namespace", "test-failure", "namespace test failure propagates"))
    rows.append(("namespace/invalid-entry", source, 'if not current or current == os.environ.get("LCK_TEST_NET_PARENT"):',
                 'if False:', "namespace", "invalid-entry", "namespace invalid entry refused"))
    rows.append(("namespace/nonrecursive", source, 'if sandbox() or isolated():', 'if False:',
                 "namespace", "nonrecursive", "namespace nonrecursive success"))
    for port in ["8332", "0008332"]:
        name = "valid-fed1/" + port
        rows.append(("invite-separator/" + port, source, '.rsplit("1", 1)', '.split("1", 1)',
                     "spawn", name, "spawn sentinel did not start: " + name))
    rows.append(("invoice-address-not-amount", source, 'amounts.extend(positional[1:2])', 'amounts.extend(args[1:])',
                 "spawn", "allowed/15", "spawn permitted sentinel starts: 15"))
    for name in S.lifecycle_cases():
        rows.append(("lifecycle/" + name, source, 'if child is not None: stop()', 'if child is not None: child.poll()',
                     "lifecycle", name, "lifecycle descendants stopped/reaped: " + name))
    assert len(rows) == 149, "network mutation inventory"
    return rows


def fingerprints():
    paths = [SOURCE, FLAGS, APP / "CyberkrillTests/Rpc.lean", APP / "CyberkrillTests.lean",
             APP / "test/rpc-client.py", Path(network.__file__), Path(S.__file__), Path(__file__),
             APP / "test/rpc-recordings.py", APP / "test/generate-rpc-recordings.py"]
    return {str(p.relative_to(APP)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def command(label, args, expected, assertion=None):
    proc = subprocess.run(["timeout", "--foreground", "180", *args], cwd=APP, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=190)
    for stream in ["stdout", "stderr"]: (LOGS / (label + "." + stream)).write_bytes(getattr(proc, stream))
    (LOGS / (label + ".status")).write_text(str(proc.returncode) + "\n")
    assert proc.returncode == expected, "mutation status " + label + ": " + proc.stderr.decode()
    if assertion:
        output = (proc.stdout + proc.stderr).decode()
        assert assertion in output and ("AssertionError:" in output or "assertion failed:" in output), "mutation detecting assertion " + label + ": " + output
    return dict(command=["timeout", "--foreground", "180", *args], status=proc.returncode, streams=str(LOGS.relative_to(APP)) + "/" + label)


def network_variant(index):
    _, path, old, new, kind, selected, _ = network_edits()[index]
    source = path.read_text()
    assert source.count(old) == 1, "unique network mutation"
    # Execute the changed real helper source. Setup and assertions remain fixed.
    changed = types.ModuleType("network")
    changed.__file__ = str(path)
    changed.__source__ = source.replace(old, new, 1)
    exec(compile(changed.__source__, str(path), "exec"), changed.__dict__)
    S.network = changed
    sys.modules["network"] = changed
    if kind == "spawn": S.spawn_checks(selected)
    elif kind == "namespace": S.namespace_checks(selected)
    else: S.lifecycle_checks(selected)


def verify():
    record = json.loads(DEST.read_bytes())
    assert record["source_sha256"] == fingerprints(), "stale RPC mutation evidence"
    expected = [r[0] for r in client_edits()] + [r[0] for r in network_edits()]
    assert [r["property"] for r in record["checks"]] == expected, "RPC mutation property inventory"
    assert record["count"] == len(record["checks"]) == 211, "RPC mutation count"
    previous = record["previous_observation"]
    assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == PREVIOUS_SHA256, "retained prior RPC observations"
    assert previous["count"] == len(previous["checks"]) == 164
    planned = client_edits() + network_edits()
    assert [(r["file"], r["replace"], r["with_text"]) for r in record["checks"]] == [
        (str(r[1].relative_to(APP)), r[2], r[3]) for r in planned], "RPC exact mutation definitions"
    for row in record["checks"]:
        assert row["red"]["status"] == 1 and row["green"]["status"] == 0
        assert row["assertion"] and row["replace"] != row["with_text"]
        if "build" in row: assert row["build"]["status"] == row["restore_build"]["status"] == 0
    assert record["restored_full"]["status"] == 0
    print("RPC mutation evidence: 62 client/capture selections; 149 separately selected safety reds; exact restoration; prior 64 edits/164 reds retained", flush=True)


def main():
    args = sys.argv[1:]
    if args == ["--verify"]: verify(); return 0
    if args[:1] == ["--network-variant"]:
        if not (network.sandbox() or network.isolated()):
            return network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), *args])
        assert network.sandbox() or network.isolated(), "mutation safety execution requires isolation"
        network_variant(int(args[1])); return 0
    assert args in [[], ["--resume"]]
    LOGS.mkdir(parents=True, exist_ok=True)
    prior = json.loads(DEST.read_bytes())
    previous = prior.get("previous_observation", prior)
    assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == PREVIOUS_SHA256, "original RPC observation"
    hashes = fingerprints()
    originals = {p: p.read_bytes() for _, p, *_ in client_edits()}
    managed = [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]
    def restore():
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try:
            for p, data in originals.items(): p.write_bytes(data); assert p.read_bytes() == data
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    def interrupt(signum, _frame): restore(); raise SystemExit(128 + signum)
    old_signals = {sig: signal.signal(sig, interrupt) for sig in managed}
    build = ["lake", "build", "cyberkrill", "CyberkrillTests"]
    records = []
    checkpoint = LOGS / "progress.json"
    if args == ["--resume"]:
        saved = json.loads(checkpoint.read_bytes())
        assert saved["source_sha256"] == hashes, "resume source fingerprints"
        records = saved["checks"]
        expected = [r[0] for r in client_edits()] + [r[0] for r in network_edits()]
        assert [r["property"] for r in records] == expected[:len(records)], "resume completed prefix"
        command("resume-build", build, 0)
    def save():
        checkpoint.write_text(json.dumps(dict(source_sha256=hashes, checks=records), indent=2) + "\n")
    try:
        for i, (name, path, old, new, test, assertion) in enumerate(client_edits()):
            if i < len(records): continue
            label = f"client-{i:02}"
            source = originals[path].decode()
            assert source.count(old) == 1, "unique client mutation " + name
            try:
                path.write_text(source.replace(old, new, 1))
                compiled = command(label + "-build", build, 0)
                red = command(label + "-red", test, 1, assertion)
            finally: restore()
            rebuilt = command(label + "-restore-build", build, 0)
            green = command(label + "-green", test, 0)
            records.append(dict(property=name, file=str(path.relative_to(APP)), replace=old, with_text=new,
                                assertion=assertion, build=compiled, red=red, restore_build=rebuilt, green=green))
            save()
            print(name + ": build/red/restore/green 0/1/0/0", flush=True)
        for i, (name, path, old, new, kind, selected, assertion) in enumerate(network_edits()):
            if len(client_edits()) + i < len(records): continue
            label = f"network-{i:02}"
            test = ["python3", "-B", "test/network-safety.py", "--" + kind, selected]
            # Each child is re-executed into a fresh namespace by the unchanged wrapper.
            red = command(label + "-red", ["python3", "-B", "test/rpc-client-mutations.py", "--network-variant", str(i)], 1, assertion)
            green = command(label + "-green", test, 0)
            records.append(dict(property=name, file=str(path.relative_to(APP)), replace=old, with_text=new,
                                assertion=assertion, red=red, green=green))
            save()
            print(name + ": red/green 1/0", flush=True)
        full = command("restored-full", ["lake", "test"], 0)
        assert fingerprints() == hashes, "RPC exact source restoration"
        DEST.write_text(json.dumps(dict(count=len(records), source_sha256=hashes, checks=records, restored_full=full,
                                       previous_observation=previous), indent=2) + "\n")
        verify()
    finally:
        restore()
        for sig, handler in old_signals.items(): signal.signal(sig, handler)
    return 0


if __name__ == "__main__": sys.exit(main())
