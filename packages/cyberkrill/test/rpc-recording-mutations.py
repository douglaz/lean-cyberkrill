#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent offline regressions with one isolated source edit per property."""
import ast
import copy
from contextlib import redirect_stdout
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import subprocess
import sys
from unittest.mock import patch

G = importlib.import_module("generate-rpc-recordings")
R = importlib.import_module("rpc-recordings")
S = importlib.import_module("rpc-recording-safety")


def repair_checks(g=G, r=R):
    """Source-bound behavioral regressions, also runnable against an older source."""
    rows = G.inventory()
    shared = {n: (G.HERE / "recordings" / n).read_bytes() for n in G.SHARED}
    data = {row["name"]: G.parse_json((G.HERE / "recordings" / row["recording"]).read_bytes()) for row in rows}
    checks = {}
    descriptors = json.loads(shared["shared/descriptors.json"])

    def cli_text():
        # Extract only the production CLI adapter: no node, namespace or wallet.
        source = getattr(g, "__source__", Path(g.__file__).read_text())
        capture = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "capture_case")
        cli = next(n for n in capture.body if isinstance(n, ast.FunctionDef) and n.name == "cli")
        scope = dict(cli_base=["bitcoin-cli"], run=lambda *a, **kw: types.SimpleNamespace(stdout=payload),
                     parse_json=G.parse_json, json_text=G.json_text)
        exec(compile(ast.Module(body=[cli], type_ignores=[]), g.__file__, "exec"), scope)
        for method, payload, expected in [
            ("sendtoaddress", b"1e" + b"9" * 62 + b"\n", "1e" + "9" * 62),
            ("sendtoaddress", b"1" * 64 + b"\n", "1" * 64),
            ("getnewaddress", b"bcrt1-disposable\n", "bcrt1-disposable"),
            ("getblockchaininfo", b'{"chain":"regtest"}\n', {"chain": "regtest"}),
        ]:
            try: actual = scope["cli"](method)
            except ArithmeticError as error:
                raise AssertionError("CLI textual RPC results retain exact strings") from error
            assert actual == expected, "CLI textual RPC results retain exact strings"
    checks["cli-text"] = cli_text

    def fallback_order(name):
        row = next(row for row in rows if row["name"] == name)
        value = data[name]
        class Replies:
            def __init__(self): self.calls = []
            def record(self, method, params, wallet):
                self.calls.append((method, params, wallet))
                if method in ["createpsbt", "walletcreatefundedpsbt"]: return None
                entry = next(e for e in value["entries"] if e["rpc"]["method"] == method and
                             any(G.selector(p) == G.selector(params) for p in e["rpc"]["params"]))
                return R.result(entry)
        capture = Replies()
        funding = [{**p, "sats": int(p["sats"]), "vout": int(p["vout"])} for p in value["capture"]["funding"]]
        g.fallback(capture, row, descriptors, {"single": [["destination"] * 6]}, funding)
        actual = next(p[0] for m, p, _ in capture.calls if m in ["createpsbt", "walletcreatefundedpsbt"])
        expected = next(e["rpc"]["params"][0][0] for e in value["entries"] if e["rpc"]["method"] in ["createpsbt", "walletcreatefundedpsbt"])
        assert actual == expected, "fallback descriptor reply order: " + name

    for name in ["multipath-create", "change-funded"]:
        checks["order-" + name] = lambda name=name: fallback_order(name)

    def duplicate_scope():
        a, b, c = [dict(txid=letter * 64, vout=0, amount=G.Decimal("0.1")) for letter in ["a", "b", "c"]]
        class Replies:
            def record(self, method, params, wallet):
                if method == "getdescriptorinfo": return dict(descriptor=params[0])
                if method == "deriveaddresses": return [params[0]]
                if method == "listunspent":
                    return [b, a, b] if params[2] == ["wpkh(0/*)"] else [a, c, b, c]
                return None  # Ignored descriptor-import error.
        outpoints = [{**a, "sats": 10000000}, {**b, "sats": 10000000}, {**c, "sats": 10000000}]
        inputs = ["{first}", "{first}", "{descriptor}", "{descriptor}", "{second}"]
        actual = g.expand_inputs(Replies(), inputs, "single", "wpkh(<0;1>/*)", outpoints)
        assert [p["txid"] for p in actual] == [p["txid"] for p in [a, a, b, a, c, b, a, c, b]], "per-descriptor first-seen duplicate scope"
    checks["duplicate-scope"] = duplicate_scope

    def checker_scope():
        funding = [dict(txid=letter * 64, vout=0, sats=10000000) for letter in ["a", "b", "c"]]
        a, b, c = [dict(txid=p["txid"], vout=p["vout"], amount=G.Decimal("0.1")) for p in funding]
        methods = {name: [] for name in ["getdescriptorinfo", "deriveaddresses", "listunspent"]}
        def entry(params, result):
            return dict(rpc=dict(params=[params]), responses=[dict(status=200, text=G.json_text(dict(jsonrpc="2.0", id=1, result=result)))])
        for branch, unspent in [(0, [b, a, b]), (1, [a, c, b, c])]:
            desc = f"wpkh({branch}/*)"
            methods["getdescriptorinfo"].append(entry([desc], dict(descriptor=desc)))
            methods["deriveaddresses"].append(entry([desc, [0, 99]], [desc]))
            methods["listunspent"].append(entry([0, 9999999, [desc]], unspent))
        row = dict(args=["--inputs", "{first}", "--inputs", "{first}", "--inputs", "{descriptor}", "--inputs", "{descriptor}", "--inputs", "{second}"])
        actual = r.expected_inputs(row, methods, "wpkh(<0;1>/*)", funding)
        assert actual == [dict(txid=p["txid"], vout=p["vout"]) for p in [a, a, b, a, c, b, a, c, b]], "independent input expansion duplicate scope/order"
    checks["checker-scope"] = checker_scope

    # Each precision selector is tested independently, with original replies/bindings.
    for name in ["multipath-create", "change-funded", "move-success", "move-overshoot", "move-f64"]:
        row = next(row for row in rows if row["name"] == name)
        original = data[name]
        indices = [i for i, e in enumerate(original["entries"]) if e["rpc"]["method"] in ["createpsbt", "walletcreatefundedpsbt"]]
        for variant, index in enumerate(indices):
            for damage in ["foreign", "wrong", "missing", "extra", "reordered", "boolean"]:
                inputs = original["entries"][index]["rpc"]["params"][0][0]
                if damage == "reordered" and len(inputs) < 2: continue
                def correspondence(row=row, original=original, index=index, damage=damage):
                    r.validate_case(row, original, shared)
                    changed = copy.deepcopy(original)
                    inputs = changed["entries"][index]["rpc"]["params"][0][0]
                    if damage == "foreign":
                        foreign = data["move-success" if row["name"] == "move-f64" else "move-f64"]["capture"]["funding"][0]
                        inputs[0] = dict(txid=foreign["txid"], vout=foreign["vout"])
                    elif damage == "wrong": inputs[0]["vout"] += 1
                    elif damage == "missing": inputs.pop()
                    elif damage == "extra": inputs.append(copy.deepcopy(inputs[0]))
                    elif damage == "boolean": inputs[0]["vout"] = bool(inputs[0]["vout"])
                    else: inputs.reverse()
                    changed["capture"]["entries_sha256"] = G.digest(G.encoded(changed["entries"]))
                    rejected(lambda: r.validate_case(row, changed, shared), "ordered case-local PSBT inputs")
                checks[f"inputs-{name}-{variant}-{damage}"] = correspondence

    def policy_checker():
        changed = copy.deepcopy(data["move-success"])
        changed["capture"].update(producer="source-client", reference_result=dict(status=1, stdout="", stderr="disposable reference failure"),
                                  first_case_attempts=[dict(status=1, stdout="", stderr="disposable reference failure", qualifying_capture=False)] * 2)
        blobs = {row["recording"]: G.encoded(changed if row["name"] == "move-success" else data[row["name"]]) for row in rows}
        rejected(lambda: r.validate_bundle(rows, blobs, shared), "consistent non-DCA producer policy")
        # DCA is an exception; a uniformly source-client corpus is also permitted.
        fallback = copy.deepcopy(data)
        for row in rows:
            if row["kind"] == "dca": continue
            fallback[row["name"]]["capture"].update(producer="source-client", reference_result=None,
                first_case_attempts=[dict(status=1, stdout="", stderr="disposable reference failure", qualifying_capture=False)] * 2)
        r.validate_bundle(rows, {row["recording"]: G.encoded(fallback[row["name"]]) for row in rows}, shared)
    checks["policy-checker"] = policy_checker

    def policy_publication(metadata=False):
        with tempfile.TemporaryDirectory(prefix="rpc-policy-", dir=os.environ["TMPDIR"]) as temp:
            here = Path(temp) / "package/test"
            here.mkdir(parents=True)
            destination = here / "recordings"
            destination.mkdir()
            for name, blob in {**shared, **{row["recording"]: G.encoded(data[row["name"]]) for row in rows}}.items():
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(blob)
            inventory = G.HERE / "rpc-recording-cases.json"
            (here / inventory.name).write_bytes(inventory.read_bytes())
            before = {p.relative_to(here).as_posix(): p.read_bytes() for p in here.rglob("*") if p.is_file()}
            changed = copy.deepcopy(data["move-success"])
            attempts = [dict(status=1, stdout="", stderr="disposable reference failure", qualifying_capture=False)] * 2
            changed["capture"].update(producer="source-client", reference_result={k: attempts[-1][k] for k in ["status", "stdout", "stderr"]}, first_case_attempts=attempts)
            if metadata:
                changed = copy.deepcopy(data["move-success"])
                changed["capture"]["reference_result"] = None
            class Replies:
                def __init__(self): self.calls = []
                def record(self, method, params, wallet):
                    self.calls.append((method, params))
                    entry = next(e for e in changed["entries"] if e["rpc"]["method"] == method and
                                 any(G.selector(p) == G.selector(params) for p in e["rpc"]["params"]))
                    return R.result(entry)
            class Worker:
                pid = 0
                returncode = 0
                def __init__(self, *args, **kwargs): pass
                def communicate(self, payload, timeout):
                    # Simulate the worker's failed reference route, then execute
                    # the actual offline fallback against case-local Core replies.
                    capture = Replies()
                    row = next(r for r in rows if r["name"] == "move-success")
                    psbt = next(e for e in changed["entries"] if e["rpc"]["method"] == "createpsbt")
                    destination = next(iter(psbt["rpc"]["params"][0][1]))
                    funding = [{**p, "sats": int(p["sats"]), "vout": int(p["vout"])} for p in changed["capture"]["funding"]]
                    g.fallback(capture, row, descriptors, {"single": [[destination] * 6]}, funding)
                    assert len(capture.calls) == 2, "selected fallback actually executed"
                    return G.encoded({"move-success": changed}), None
                def poll(self): return 0
            # No namespace, node, tool derivation or external reference is executed.
            with patch.object(g, "HERE", here), patch.object(g, "public_inputs", lambda: shared), \
                 patch.object(g, "run", lambda args, **kw: types.SimpleNamespace(stdout=("synthetic:x:1:1::/disposable:/bin/sh\n" if args[0] == "getent" else args[-1] + "\n").encode())), \
                 patch.object(g.subprocess, "Popen", Worker), patch.object(g, "reap_group", lambda worker: None), \
                 patch.object(g.importlib.metadata, "version", lambda name: "disposable"), \
                 patch.object(sys, "argv", ["capture", "--cases", "move-success", "--reference", str(Path(G.__file__)), "--reference-source", str(here)]):
                # Preserve source-pin validation with the real immutable source content digest.
                source = {p: b"disposable immutable source" for p in g.SOURCE_HASHES}
                for name, blob in source.items():
                    path = here / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(blob)
                with patch.object(g, "SOURCE_HASHES", {n: G.digest(b) for n, b in source.items()}):
                    rejected(g.main, "reference-proxy execution evidence" if metadata else "consistent non-DCA producer policy")
            after = {p.relative_to(here).as_posix(): p.read_bytes() for p in here.rglob("*") if p.is_file() and not p.is_relative_to(here / "cyberkrill-core") and not p.is_relative_to(here / "cyberkrill")}
            assert before == after, "policy refusal preserves every published artifact and inventory"
    checks["policy-publication"] = policy_publication
    for mode in ["explicit", "inherited"]:
        for worker in [False, True]:
            def optimization(mode=mode, worker=worker):
                # Load the actual source, with synthetic identity/path commands and
                # effect sentinels. Even an unfixed optimized entry cannot go live.
                probe = '''import pathlib, sys, types
source = pathlib.Path(sys.argv[1])
module = types.ModuleType("entry_probe")
module.__file__ = str(source)
try:
    exec(compile(source.read_bytes(), str(source), "exec"), module.__dict__)
except RuntimeError as error:
    if str(error) != "optimized Python execution refused": raise
    print("optimization refused before identity, derivation, paths or worker effects")
    sys.exit(0)
def fake_run(args, **kwargs):
    output = "synthetic:x:1:1::/disposable:/bin/sh\\n" if args[0] == "getent" else args[-1] + "\\n"
    return types.SimpleNamespace(stdout=output.encode())
def effect(*args, **kwargs): raise RuntimeError("UNSAFE optimized entry reached effects")
module.run = fake_run
module.public_inputs = effect
module.inside = effect
sys.argv = [str(source), "--inside"] if sys.argv[2] == "worker" else [str(source), "--network", "mainnet", "--rpcport", "8332", "--rpc-host", "example.invalid"]
if sys.argv[1:] == ["--inside"]:
    import io
    sys.stdin = io.StringIO("{}")
module.main()
raise RuntimeError("UNSAFE optimized entry returned")
'''
                env = dict(os.environ)
                env.pop("PYTHONOPTIMIZE", None)
                args = [sys.executable, "-B"]
                if mode == "explicit": args.append("-O")
                else: env["PYTHONOPTIMIZE"] = "2"
                proc = subprocess.run([*args, "-c", probe, g.__file__, "worker" if worker else "manual"],
                                      env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
                assert proc.returncode == 0 and b"optimization refused before" in proc.stdout and not proc.stderr, \
                    "optimized entry refusal: " + mode + (" worker" if worker else " manual") + ": " + proc.stderr.decode()
            checks["optimization-" + mode + ("-worker" if worker else "-manual")] = optimization
    return checks


def repair_main():
    names = sys.argv[2:] or list(repair_checks())
    sources = {Path(m.__file__).name: G.digest(Path(m.__file__).read_bytes()) for m in [G, R, S]}
    suite_sha256 = G.digest(Path(__file__).read_bytes())
    for name in names:
        repair_checks()[name]()
        print("RPC repair " + name + ": green", flush=True)
    assert sources == {Path(m.__file__).name: G.digest(Path(m.__file__).read_bytes()) for m in [G, R, S]}, "repair source restoration"
    directory = G.HERE.parent / ".lake/validation"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "rpc-repairs.json").write_text(json.dumps(dict(count=len(names), checks=names, source_sha256=sources, suite_sha256=suite_sha256), indent=2) + "\n")


def repair_edits():
    return [
        ("order-multipath-create", G, 'selected.append({**utxo, "sats": int(utxo["amount"] * Decimal(100000000))})',
         'selected.append({**utxo, "sats": int(utxo["amount"] * Decimal(100000000))}); selected.sort(key=lambda p: next(i for i, o in enumerate(outpoints) if o["txid"] == p["txid"]))'),
        ("duplicate-scope", G, 'if key not in seen:', 'if True:'),
        ("duplicate-scope", G, 'for expanded in branches:', 'for expanded in branches:\n                seen = set()'),
        ("duplicate-scope", G, 'seen = set()\n            for expanded', 'seen = set((p["txid"], p["vout"]) for p in selected)\n            for expanded'),
        ("duplicate-scope", G, 'selected.append(outpoints[["{first}", "{second}", "{third}"].index(input)])',
         'p = outpoints[["{first}", "{second}", "{third}"].index(input)]; selected.extend([] if p in selected else [p])'),
        ("inputs-multipath-create-0-foreign", R, 'assert G.selector(params[0]) == G.selector(expected), "ordered case-local PSBT inputs: " + row["name"]', 'assert True'),
        ("checker-scope", R, 'if key in seen: continue', 'if False: continue'),
        ("checker-scope", R, 'seen = set()\n            for branch', 'seen = set((p["txid"], p["vout"]) for p in expanded)\n            for branch'),
        ("policy-checker", R, 'and len(producers) <= 1', 'and True'),
        ("policy-publication", G, 'checker.check_producers(all_rows, corpus)', 'pass'),
        ("cli-text", G, 'if method in ["sendtoaddress", "getnewaddress"]: return output', 'pass'),
    ]


def repair_variant(index):
    name, module, old, new = repair_edits()[index]
    source = Path(module.__file__).read_text()
    assert source.count(old) == 1, "unique repair mutation: " + name
    variant = types.ModuleType(module.__name__)
    variant.__file__ = module.__file__
    variant.__source__ = source.replace(old, new, 1)
    exec(compile(variant.__source__, module.__file__, "exec"), variant.__dict__)
    repair_checks(**{"g" if module is G else "r": variant})[name]()


def repair_mutations():
    """Actual child statuses/streams; existing thirty remain separate."""
    originals = {Path(m.__file__): Path(m.__file__).read_bytes() for m in [G, R, S]}
    logs = G.HERE.parent / ".lake/validation"
    records = []
    for index, (name, module, old, new) in enumerate(repair_edits()):
        observations = []
        for phase, args, expected in [
            ("before", ["--repair-check", name], 0),
            ("red", ["--repair-variant", str(index)], 1),
            ("after", ["--repair-check", name], 0),
        ]:
            command = [sys.executable, "-B", str(Path(__file__).resolve()), *args]
            proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            prefix = logs / f"rpc-repair-{index}-{phase}"
            for stream in ["stdout", "stderr"]: prefix.with_suffix("." + stream).write_bytes(getattr(proc, stream))
            prefix.with_suffix(".status").write_text(str(proc.returncode) + "\n")
            assert proc.returncode == expected, "repair child status: " + name + ": " + proc.stderr.decode()
            if phase == "red":
                failure = next((line for line in reversed(proc.stderr.decode().splitlines()) if line.startswith("AssertionError:")), "")
                assert failure and "wrong detecting assertion" not in failure, "named repair assertion: " + proc.stderr.decode()
                assert not any(error in proc.stderr.decode() for error in ["SyntaxError:", "NameError:", "ModuleNotFoundError:", "FileNotFoundError:"]), "repair setup failure"
            observations.append(dict(phase=phase, command=command, status=proc.returncode, streams=prefix.name))
        assert all(p.read_bytes() == b for p, b in originals.items()), "repair mutation restoration"
        records.append(dict(property=name, file=Path(module.__file__).name, replace=old, with_text=new, failure=failure, observations=observations))
        print(f"RPC repair mutation {name}: red 1 ({failure}); original green 0")
    assert len(records) == 11, "independent repair mutation count"
    (logs / "rpc-repair-mutations.json").write_text(json.dumps(dict(count=len(records), edits=records,
        source_sha256={p.name: G.digest(b) for p, b in originals.items()}, suite_sha256=G.digest(Path(__file__).read_bytes())), indent=2) + "\n")


def rejected(operation, assertion):
    try: operation()
    except (AssertionError, ValueError, KeyError) as error:
        assert assertion in str(error), "wrong detecting assertion: " + str(error)
    else: raise AssertionError("missing refusal: " + assertion)


def metadata_checks(r=R):
    """Metadata-only corruptions retain every entry, reply, digest and binding."""
    rows = G.inventory()
    shared = {n: (G.HERE / "recordings" / n).read_bytes() for n in G.SHARED}
    data = {row["name"]: G.parse_json((G.HERE / "recordings" / row["recording"]).read_bytes()) for row in rows}
    def validate(cases):
        with redirect_stdout(io.StringIO()):
            r.validate_bundle(rows, {row["recording"]: G.encoded(cases[row["name"]]) for row in rows}, shared)
    def unchanged(cases):
        for name, original in data.items():
            assert cases[name]["entries"] == original["entries"], "metadata probe preserves entries/replies"
            assert cases[name]["binding"] == original["binding"], "metadata probe preserves definition/shared bindings"
            assert cases[name]["capture"]["entries_sha256"] == original["capture"]["entries_sha256"], "metadata probe preserves content digest"
    failed = dict(status=1, stdout="", stderr="disposable reference failure", qualifying_capture=False)
    incomplete = dict(status=0, stdout="{}", stderr="", qualifying_capture=False)
    def fallback():
        cases = copy.deepcopy(data)
        for row in rows:
            if row["kind"] != "dca":
                cases[row["name"]]["capture"].update(producer="source-client", reference_result=None,
                    first_case_attempts=[copy.deepcopy(incomplete), copy.deepcopy(failed)])
        cases["single-list"]["capture"]["reference_result"] = {k: failed[k] for k in ["status", "stdout", "stderr"]}
        return cases
    checks = {}
    def negative(name, edit, assertion, source=None):
        def check():
            cases = source() if source else copy.deepcopy(data)
            edit(cases)
            unchanged(cases)
            rejected(lambda: validate(cases), assertion)
        checks["metadata-" + name] = check
    def meta(cases): return cases["move-success"]["capture"]
    def non_dca(cases): return [cases[row["name"]]["capture"] for row in rows if row["kind"] != "dca"]
    negative("relabel", lambda cases: [m.update(producer="source-client") for m in non_dca(cases)], "fallback requires two failed reference attempts")
    negative("null-result", lambda cases: meta(cases).update(reference_result=None), "reference-proxy execution evidence")
    negative("empty-attempts", lambda cases: [m.update(first_case_attempts=[]) for m in non_dca(cases)], "bounded first-case attempts")
    negative("missing-keys", lambda cases: [(m.pop("reference_result"), m.pop("first_case_attempts")) for m in non_dca(cases)], "required capture attempt metadata")
    negative("missing-result", lambda cases: meta(cases).pop("reference_result"), "required capture attempt metadata")
    negative("missing-attempts", lambda cases: meta(cases).pop("first_case_attempts"), "required capture attempt metadata")
    negative("attempt-list", lambda cases: meta(cases).update(first_case_attempts={}), "bounded first-case attempts")
    negative("too-many", lambda cases: meta(cases).update(first_case_attempts=[failed, failed, meta(cases)["first_case_attempts"][-1]]), "bounded first-case attempts")
    for name, value in dict(null=None, status_only=dict(status=0), boolean=dict(status=True, stdout="", stderr=""),
                            fractional=dict(status=G.Decimal("0.5"), stdout="", stderr=""),
                            string=dict(status="0", stdout="", stderr=""),
                            stdout=dict(status=0, stdout=None, stderr=""),
                            stderr=dict(status=0, stdout="", stderr=[]),
                            qualification={**failed, "qualifying_capture": "false"}).items():
        negative("attempt-" + name, lambda cases, value=value: meta(cases).update(first_case_attempts=[value]), "capture execution record")
    negative("malformed-result", lambda cases: meta(cases).update(reference_result={}), "capture execution record")
    negative("reference-timeout", lambda cases: meta(cases)["reference_result"].update(status=124), "reference-proxy execution evidence")
    negative("reference-unqualified", lambda cases: meta(cases).update(first_case_attempts=[incomplete]), "reference first-case qualification")
    negative("reference-prefix", lambda cases: meta(cases).update(first_case_attempts=[{**failed, "qualifying_capture": True}, meta(cases)["first_case_attempts"][-1]]), "first-case retry evidence")
    negative("fallback-one", lambda cases: meta(cases).update(first_case_attempts=[failed]), "fallback requires two failed reference attempts", fallback)
    negative("fallback-qualified", lambda cases: meta(cases)["first_case_attempts"][0].update(qualifying_capture=True), "fallback requires two failed reference attempts", fallback)
    negative("fallback-unexplained", lambda cases: meta(cases)["first_case_attempts"][0].pop("qualifying_capture"), "fallback requires two failed reference attempts", fallback)
    negative("fallback-result", lambda cases: meta(cases).update(reference_result=dict(status=0, stdout="unrelated", stderr="")), "fallback per-case reference evidence", fallback)
    qualified = dict(status=0, stdout="disposable completed capture", stderr="", qualifying_capture=True)
    for name, status in [("status2", 2), ("signal", -9)]:
        negative("qualified-" + name, lambda cases, status=status: meta(cases).update(first_case_attempts=[{**qualified, "status": status}]), "first-case qualification status")
    for name, attempts, assertion in [
        ("prefix", [qualified, qualified], "first-case retry evidence"),
        ("unexhausted", [failed], "fallback requires two failed reference attempts"),
        ("timeout", [{**qualified, "status": 124}], "first-case qualification status"),
        ("signal", [{**qualified, "status": -9}], "first-case qualification status"),
        ("status2", [{**qualified, "status": 2}], "first-case qualification status"),
    ]:
        negative("dca-" + name, lambda cases, attempts=attempts: cases["dca"]["capture"].update(first_case_attempts=copy.deepcopy(attempts)), assertion)
    for name, case, attempts in [
        ("qualified-zero", "move-success", [qualified]),
        ("carried-precision", "move-success", [{**qualified, "status": 1}]),
        ("incomplete-retry", "move-success", [incomplete, qualified]),
        ("dca-empty", "dca", []),
        ("dca-historical", "dca", data["single-list"]["capture"]["first_case_attempts"]),
        ("dca-success", "dca", [qualified]),
        ("dca-precision-retry", "dca", [incomplete, {**qualified, "status": 1}]),
        ("dca-exhausted", "dca", [incomplete, {**failed, "status": -9}]),
        ("dca-timeout-retry", "dca", [{**failed, "status": 124}, qualified]),
    ]:
        def positive(case=case, attempts=attempts):
            cases = copy.deepcopy(data)
            cases[case]["capture"]["first_case_attempts"] = copy.deepcopy(attempts)
            unchanged(cases)
            validate(cases)
        checks["metadata-valid-" + name] = positive
    def positives():
        validate(data)  # Includes real success, precision exit1 and DCA without attempts.
        cases = fallback()
        unchanged(cases)
        validate(cases)  # Includes exit0/incomplete and later null per-case results.
        cases["dca"]["capture"]["first_case_attempts"] = copy.deepcopy(cases["single-list"]["capture"]["first_case_attempts"])
        validate(cases)  # Carried attempts do not mean DCA executed the reference.
        cases = copy.deepcopy(data)
        for m in non_dca(cases):
            m["first_case_attempts"] = [copy.deepcopy(incomplete), {**m["first_case_attempts"][-1], "qualifying_capture": True}]
        validate(cases)  # Honest retry, including precision exit1 qualification.
        cases = copy.deepcopy(data)
        cases["move-success"]["capture"]["first_case_attempts"] = copy.deepcopy(data["move-f64"]["capture"]["first_case_attempts"])
        validate(cases)  # A carried precision result differs from this case's result.
    checks["metadata-valid-controls"] = positives
    checks["metadata-publication"] = lambda: repair_checks()["policy-publication"](True)
    return checks


def metadata_main():
    names = sys.argv[2:] or list(metadata_checks())
    for name in names:
        metadata_checks()[name]()
        print("RPC " + name + ": green", flush=True)
    if not sys.argv[2:]:
        assert len(names) == 42, "independent metadata control count"
        directory = G.HERE.parent / ".lake/validation"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "rpc-metadata-controls.json").write_text(json.dumps(dict(count=len(names), checks=names,
            source_sha256={Path(m.__file__).name: G.digest(Path(m.__file__).read_bytes()) for m in [G, R, S]},
            suite_sha256=G.digest(Path(__file__).read_bytes())), indent=2) + "\n")
        print("RPC capture metadata: 42/42 controls, including 32 refusals and 10 positive controls/groups")


def metadata_edits():
    return [
        ("metadata-missing-keys", 'assert "reference_result" in meta and "first_case_attempts" in meta, "required capture attempt metadata"', 'if "reference_result" not in meta or "first_case_attempts" not in meta: return'),
        ("metadata-too-many", 'assert isinstance(attempts, list) and (0 if row["kind"] == "dca" else 1) <= len(attempts) <= 2', 'assert True'),
        ("metadata-attempt-status_only", 'assert isinstance(value, dict) and {"status", "stdout", "stderr"} <= value.keys()', 'value.setdefault("stdout", ""); value.setdefault("stderr", ""); assert True'),
        ("metadata-attempt-boolean", 'assert type(status) in [int, Decimal] and Decimal(status).is_finite() and status == int(status)', 'assert True'),
        ("metadata-attempt-stdout", 'assert all(isinstance(value[k], str) for k in ["stdout", "stderr"])', 'assert True'),
        ("metadata-attempt-qualification", 'assert "qualifying_capture" not in value or type(value["qualifying_capture"]) is bool, "capture execution record"', 'if "qualifying_capture" in value: value["qualifying_capture"] = bool(value["qualifying_capture"])'),
        ("metadata-null-result", 'assert reference is not None and reference["status"] != 124', 'assert True'),
        ("metadata-reference-unqualified", 'assert attempts[-1].get("qualifying_capture", True) is True, "reference first-case qualification"', 'assert True, "reference first-case qualification"'),
        ("metadata-reference-prefix", 'assert all(a.get("qualifying_capture") is False for a in attempts[:-1])', 'assert True'),
        ("metadata-fallback-one", 'assert len(attempts) == 2 and all(a.get("qualifying_capture") is False for a in attempts)', 'assert True'),
        ("metadata-fallback-result", 'assert reference is None or reference == {k: attempts[-1][k] for k in ["status", "stdout", "stderr"]}', 'assert True'),
        ("metadata-publication", '    check_capture(row, meta)', '    pass'),
        ("metadata-qualified-status2", 'assert attempts[-1]["status"] in [0, 1]', 'assert attempts[-1]["status"] in [0, 1, 2]'),
        ("metadata-qualified-signal", 'assert attempts[-1]["status"] in [0, 1]', 'assert attempts[-1]["status"] in [0, 1, -9]'),
        ("metadata-dca-timeout", 'assert attempts[-1]["status"] in [0, 1]', 'assert attempts[-1]["status"] in [0, 1, 124]'),
        ("metadata-dca-prefix", 'assert all(a.get("qualifying_capture") is False for a in attempts[:-1])', 'assert row["kind"] == "dca" or all(a.get("qualifying_capture") is False for a in attempts[:-1])'),
        ("metadata-dca-unexhausted", 'assert len(attempts) == 2 and attempts[0].get("qualifying_capture") is False', 'assert True'),
    ]


def metadata_variant(index):
    name, old, new = metadata_edits()[index]
    source = Path(R.__file__).read_text()
    assert source.count(old) == 1, "unique metadata mutation: " + name
    variant = types.ModuleType(R.__name__)
    variant.__file__ = R.__file__
    exec(compile(source.replace(old, new, 1), R.__file__, "exec"), variant.__dict__)
    with patch.dict(sys.modules, {R.__name__: variant}):
        metadata_checks(r=variant)[name]()


def metadata_mutations():
    logs = G.HERE.parent / ".lake/validation"
    originals = {Path(m.__file__): Path(m.__file__).read_bytes() for m in [G, R, S]}
    records = []
    for index, (name, old, new) in enumerate(metadata_edits()):
        observations = []
        for phase, args, expected in [("before", ["--metadata", name], 0),
                                      ("red", ["--metadata-variant", str(index)], 1),
                                      ("after", ["--metadata", name], 0)]:
            command = [sys.executable, "-B", str(Path(__file__).resolve()), *args]
            proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            prefix = logs / f"rpc-metadata-{index}-{phase}"
            for stream in ["stdout", "stderr"]: prefix.with_suffix("." + stream).write_bytes(getattr(proc, stream))
            prefix.with_suffix(".status").write_text(str(proc.returncode) + "\n")
            assert proc.returncode == expected, "metadata child status: " + name + ": " + proc.stderr.decode()
            if phase == "red":
                failure = proc.stderr.decode().splitlines()[-1]
                assert failure.startswith("AssertionError: missing refusal:"), "named metadata assertion: " + proc.stderr.decode()
            observations.append(dict(phase=phase, command=command, status=proc.returncode, streams=prefix.name))
        assert all(p.read_bytes() == b for p, b in originals.items()), "metadata source restoration"
        records.append(dict(property=name, replace=old, with_text=new, failure=failure, observations=observations))
        print("RPC metadata mutation " + name + ": before/red/after 0/1/0", flush=True)
    assert len(records) == 17, "independent metadata mutation count"
    (logs / "rpc-metadata-mutations.json").write_text(json.dumps(dict(count=len(records), edits=records,
        source_sha256={p.name: G.digest(b) for p, b in originals.items()},
        suite_sha256=G.digest(Path(__file__).read_bytes())), indent=2) + "\n")


def controls(g=G, r=R, s=S):
    rows = G.inventory()
    root = G.HERE / "recordings"
    shared = {name: (root / name).read_bytes() for name in G.SHARED}
    data = {row["name"]: G.parse_json((root / row["recording"]).read_bytes()) for row in rows}
    row = next(row for row in rows if row["name"] == "move-f64")
    value = data[row["name"]]
    def checked(value=value, row=row, shared=shared): r.validate_case(row, value, shared)
    def corrupt(edit, assertion):
        changed = copy.deepcopy(value)
        edit(changed)
        # Rebind the untrusted content digest so semantic tests reach their property.
        changed["capture"]["entries_sha256"] = G.digest(G.encoded(changed["entries"]))
        rejected(lambda: checked(changed), assertion)
    def definition_command():
        bad = {**row, "command": "onchain-list-utxos"}
        rejected(lambda: g.validate_definition(bad), "command/kind consistency")
    def definition_args():
        bad = {**row, "args": row["args"][:-2]}
        rejected(lambda: g.validate_definition(bad), "command argument shape")
    def arithmetic():
        class Collector:
            def __init__(self): self.calls = []
            def record(self, method, params, wallet): self.calls.append((method, params))
        collector = Collector()
        desc = json.loads(shared["shared/descriptors.json"])
        addresses = {"single": [["bcrt1-test"] * 6]}
        funding = [{**p, "sats": int(p["sats"]), "vout": int(p["vout"])} for p in value["capture"]["funding"]]
        g.fallback(collector, row, desc, addresses, funding)
        assert list(collector.calls[-1][1][1].values()) == [G.Decimal("0.6999833999999999")], "ordered source float regression"
    def key_scan():
        rejected(lambda: s.portable("sample.json", json.dumps({"data": "tprv" + "1" * 104}).encode()), "private extended key")
    def private_field():
        rejected(lambda: s.portable("sample.json", b'{"capture":{"seed":"forbidden"}}'), "private field")
    def metadata(): s.portable("move-f64.json", b'{"capture":{"tools":{"mnemonic":"0.21"}}}')
    def provenance_output():
        rejected(lambda: s.portable("shared/provenance.json", b'{"derivation":{"mnemonic":"forbidden phrase"}}'), "private field")
    def version_output():
        rejected(lambda: s.portable("shared/provenance.json", b'{"derivation":{"versions":{"mnemonic":"forbidden phrase"}}}'), "private field")
    def credentials():
        rejected(lambda: s.portable("sample.json", b'{"other":"Basic wrong"}'), "unexpected Basic credentials")
    def rpcauth():
        rejected(lambda: s.portable("sample.json", b'{"rpcauth":"lck:changed"}'), "unexpected rpcauth credentials")
    def home_path():
        rejected(lambda: s.portable("sample.json", b'{"data":"~/private-node"}'), "home-relative path")
    def selector():
        assert g.selector([9007199254740992]) != g.selector([9007199254740993]), "exact large-integer selector"
        assert g.selector([True]) != g.selector([1]), "boolean selector distinction"
        assert g.selector([1, 2]) != g.selector([2, 1]), "selector array order"
        assert g.selector([1]) == g.selector([G.Decimal("1.0")]), "exact numeric equivalence"
    def body():
        expected = value["entries"][0]["responses"][0]
        rejected(lambda: r.assert_response((expected["status"], expected["headers"], b"changed"), expected), "replay full response bytes")
    def headers():
        rejected(lambda: r.assert_response((200, {}, b"payload"), dict(status=200, headers={"x-required": "retained"}, text="payload")), "replay full retained headers")
    def status():
        rejected(lambda: r.assert_response((201, {}, b"payload"), dict(status=200, headers={}, text="payload")), "replay status")
    def overlap():
        entries = copy.deepcopy(value["entries"])
        entries[-1]["rpc"]["params"] = copy.deepcopy(entries[-2]["rpc"]["params"])
        rejected(lambda: r.check_selectors(entries), "overlapping exact selectors")
    def isolation():
        r.check_selectors(value["entries"])
        r.check_selectors(value["entries"])
    def method_inventory():
        corrupt(lambda d: d["entries"][0]["rpc"].update(method="getblock"), "case method inventory")
    def response_inventory():
        corrupt(lambda d: d["entries"][0]["responses"].append(copy.deepcopy(d["entries"][0]["responses"][0])), "case response inventory")
    def entry_inventory():
        corrupt(lambda d: d["entries"].pop(), "case entry completeness")
    def definition_binding():
        corrupt(lambda d: d["binding"].update(definition="0" * 64), "case definition binding")
    def shared_binding():
        corrupt(lambda d: d["binding"]["files"].update({"bitcoin-dir/.cookie": "0" * 64}), "case shared/auth binding")
    def endpoint():
        corrupt(lambda d: d["entries"][0].update(path="/wallet/multisig"), "case-local endpoint")
    def missing_recording():
        rejected(lambda: r.validate_bundle([row], {}, shared), "recording file completeness")
    def wallet():
        changed = dict(shared)
        export = json.loads(changed["shared/frozenkrill-single.json"])
        export["singlesig_receiving_output_descriptor"] = "changed"
        changed["shared/frozenkrill-single.json"] = G.encoded(export)
        changed_data = copy.deepcopy(value)
        changed_data["binding"]["files"] = {name: G.digest(blob) for name, blob in changed.items()}
        rejected(lambda: checked(changed_data, shared=changed), "wallet/descriptor correspondence")
    def shared_prelaunch():
        with tempfile.TemporaryDirectory(prefix="rpc-shared-", dir=os.environ["TMPDIR"]) as temp:
            destination = Path(temp) / "recordings"
            destination.mkdir()
            rejected(lambda: g.verify_shared(destination, shared), "selected shared drift")
            for name, blob in shared.items():
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(blob)
            (destination / "bitcoin-dir/.cookie").write_bytes(b"changed")
            rejected(lambda: g.verify_shared(destination, shared), "selected shared drift")
    def publication():
        with tempfile.TemporaryDirectory(prefix="rpc-publication-", dir=os.environ["TMPDIR"]) as temp:
            destination = Path(temp)
            for name in ["first.json", "second.json"]: (destination / name).write_bytes(b"original")
            mkstemp = tempfile.mkstemp
            count = 0
            def fail_second(*args, **kwargs):
                nonlocal count
                count += 1
                if count == 2: raise OSError("controlled staging failure")
                return mkstemp(*args, **kwargs)
            try:
                with patch.object(g.tempfile, "mkstemp", fail_second):
                    g.publish(destination, {"first.json": b"replacement", "second.json": b"replacement"})
            except OSError as error: assert str(error) == "controlled staging failure"
            else: raise AssertionError("staging failure must propagate")
            assert {p.name: p.read_bytes() for p in destination.iterdir()} == {"first.json": b"original", "second.json": b"original"}, "failed staging preserves published bytes"
    def dca_corrupt(edit, assertion):
        dca_row = next(row for row in rows if row["name"] == "dca")
        changed = copy.deepcopy(data["dca"])
        entry = next(e for e in changed["entries"] if e["rpc"]["method"] == "scantxoutset")
        reply = G.parse_json(entry["responses"][0]["text"])
        edit(reply["result"])
        entry["responses"][0]["text"] = G.json_text(reply) + "\n"
        changed["capture"]["entries_sha256"] = G.digest(G.encoded(changed["entries"]))
        rejected(lambda: r.validate_case(dca_row, changed, shared), assertion)
    def dca_chain(): dca_corrupt(lambda v: v.update(bestblock="0" * 64), "DCA scan chain snapshot")
    def dca_total(): dca_corrupt(lambda v: v.update(total_amount=v["total_amount"] + G.Decimal("0.00000001")), "DCA scan total amount")
    def dca_value(): dca_corrupt(lambda v: v["unspents"][0].update(amount=G.Decimal("0.00000001")), "DCA scan value/script correspondence")
    def dca_block(): dca_corrupt(lambda v: v["unspents"][0].update(height=0), "DCA scan block correspondence")
    def dca_origin(): dca_corrupt(lambda v: v["unspents"][0].update(desc=v["unspents"][0]["desc"].replace("[73c5da0a/", "[00000000/")), "DCA derived descriptor origin")
    def dca_hash():
        dca_row = next(row for row in rows if row["name"] == "dca")
        r.validate_case(dca_row, data["dca"], shared)
    return dict(command=definition_command, args=definition_args, arithmetic=arithmetic,
                key=key_scan, private=private_field, metadata=metadata, credentials=credentials,
                body=body, headers=headers, status=status, overlap=overlap,
                methods=method_inventory, responses=response_inventory, entries=entry_inventory,
                definition=definition_binding, shared=shared_binding, endpoint=endpoint,
                missing=missing_recording, wallet=wallet, selector=selector,
                prelaunch=shared_prelaunch, publication=publication, isolation=isolation,
                rpcauth=rpcauth, home_path=home_path, dca_chain=dca_chain,
                dca_total=dca_total, dca_value=dca_value, dca_block=dca_block,
                dca_origin=dca_origin, dca_hash=dca_hash,
                provenance_output=provenance_output, version_output=version_output)


def main():
    edits = [
        ("command", G, 'assert row["command"] == commands.get(row["kind"])', 'assert True'),
        ("args", G, 'assert len(row["args"]) == len(expected)', 'assert True'),
        ("arithmetic", G, 'for p in chosen: total += p["sats"] / 1e8', 'for p in chosen: total = p["sats"] / 1e8'),
        ("key", S, 'assert re.search(KEY_PATTERN, text) is None', 'assert True'),
        ("private", S, 'assert allowed, "private field in recording"', 'assert True, "private field in recording"'),
        ("metadata", S, 'or trail == ("capture", "tools")', 'or False'),
        ("credentials", S, 'obj == G.AUTH or challenge', 'True'),
        ("body", R, 'assert payload == expected["text"].encode()', 'assert True'),
        ("headers", R, 'assert all(folded.get(k.lower()) == v for k, v in expected["headers"].items())', 'assert True'),
        ("status", R, 'assert status == expected["status"]', 'assert True'),
        ("selector", G, 'return canonical(parse_json(json_text(value)))', 'return canonical(parse_json(json.dumps(json.loads(json_text(value), parse_int=float, parse_float=float))))'),
        ("responses", R, 'assert sum(len(e["responses"]) for e in entries) == RESPONSES[row["name"]]', 'assert True'),
        ("definition", R, 'assert data["binding"]["definition"] == G.digest(G.definition_bytes(row))', 'assert True'),
        ("shared", R, 'assert data["binding"]["files"] == {name: G.digest(value) for name, value in shared.items()}', 'assert True'),
        ("endpoint", R, 'assert entry["method"] == "POST" and entry["path"] == "/wallet/" + row["fixture"]', 'assert True'),
        ("wallet", R, 'assert exported[prefix + field + "_output_descriptor"] == descriptor.replace("<0;1>", str(branch))', 'assert True'),
        ("prelaunch", G, 'assert path.is_file() and not path.is_symlink() and path.read_bytes() == data', 'assert True'),
        ("publication", G, 'target.write(data); target.flush(); os.fsync(target.fileno())', 'target.write(data); target.flush(); os.fsync(target.fileno()); os.replace(temporary, path)'),
        ("overlap", R, 'assert key not in selectors', 'assert True'),
        ("isolation", R, 'selectors = set()', 'selectors = getattr(check_selectors, "seen", set()); check_selectors.seen = selectors'),
        ("rpcauth", S, 'assert name == "shared/provenance.json" and trail == ("auth",) and item == G.RPCAUTH', 'assert True'),
        ("home_path", S, 'assert not obj.startswith(("~/",', 'assert True or not obj.startswith(("~/",'),
        ("dca_chain", R, 'assert scanned["height"] == chain["blocks"] and scanned["bestblock"] == chain["bestblockhash"]', 'assert True'),
        ("dca_total", R, 'assert scanned["total_amount"] == Decimal(sum(int(p["sats"]) for p in expected)) / 100000000', 'assert True'),
        ("dca_value", R, 'assert utxo["amount"] == Decimal(p["sats"]) / 100000000 and utxo["scriptPubKey"] == tx["vout"][int(p["vout"])]["scriptPubKey"]["hex"]', 'assert True'),
        ("dca_block", R, 'assert utxo["height"] == block["height"] and utxo["blockhash"] == block["hash"] and utxo["confirmations"] == tx["confirmations"]', 'assert True'),
        ("dca_origin", R, 'assert utxo["desc"].startswith(prefix)', 'assert True'),
        ("dca_hash", R, 'hashlib.sha256(public_key)', 'hashlib.sha256(b"")'),
        ("provenance_output", S, 'and item == dict(', 'and True or item == dict('),
        ("version_output", S, 'version = key == "mnemonic" and item == "0.21"', 'version = key == "mnemonic"'),
    ]
    originals = {Path(module.__file__): Path(module.__file__).read_bytes() for module in [G, R, S]}
    records = []
    for name, module, old, new in edits:
        controls()[name]()
        source = originals[Path(module.__file__)].decode()
        assert source.count(old) == 1, "unique isolated source edit: " + name
        mutated = types.ModuleType(module.__name__)
        mutated.__file__ = module.__file__
        exec(compile(source.replace(old, new, 1), module.__file__, "exec"), mutated.__dict__)
        kwargs = {"g" if module is G else "r" if module is R else "s": mutated}
        try:
            with redirect_stdout(io.StringIO()): controls(**kwargs)[name]()
        except AssertionError as error:
            failure = str(error)
            assert failure, "named detecting assertion"
            assert not failure.startswith("wrong detecting assertion"), failure
        else: raise AssertionError("undetected source mutation: " + name)
        controls()[name]()
        assert all(path.read_bytes() == data for path, data in originals.items()), "unchanged original source bytes"
        records.append(dict(property=name, file=Path(module.__file__).name, replace=old, with_text=new, status=1, failure=failure, restored=0))
        print(f"RPC mutation {name}: red 1 ({failure}); original green 0")
    # Actual recursive grep with a planted long key, in a disposable copy only.
    with tempfile.TemporaryDirectory(prefix="rpc-safety-copy-", dir=os.environ["TMPDIR"]) as temp:
        import shutil
        root = Path(temp) / "recordings"
        shutil.copytree(G.HERE / "recordings", root)
        S.scan(root)
        path = root / "move-f64.json"
        path.write_bytes(path.read_bytes() + b'\ntprv' + b'1' * 104)
        rejected(lambda: S.scan(root), "recording safety grep requires exit 1")
        rejected(lambda: S.scan(root / "absent"), "real recording directory required")
    logs = G.HERE.parent / ".lake/validation"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "rpc-mutations.json").write_text(json.dumps(dict(count=len(records), edits=records,
        source_sha256={p.name: hashlib.sha256(b).hexdigest() for p, b in originals.items()}), indent=2) + "\n")
    for name, check in controls().items(): check()
    assert len(records) == 30, "independent mutation count"
    print("RPC source mutations: 30/30 detecting reds and restored greens; separate planted-key and missing-path refusals")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--metadata"]: metadata_main()
    elif sys.argv[1:2] == ["--metadata-variant"]: metadata_variant(int(sys.argv[2]))
    elif sys.argv[1:2] == ["--metadata-mutations"]: metadata_mutations()
    elif sys.argv[1:2] == ["--repairs"]: repair_main()
    elif sys.argv[1:2] == ["--repair-variant"]: repair_variant(int(sys.argv[2]))
    elif sys.argv[1:2] == ["--repair-check"]: repair_checks()[sys.argv[2]]()
    else:
        main()
        repair_main()
        repair_mutations()
        metadata_main()
        metadata_mutations()
