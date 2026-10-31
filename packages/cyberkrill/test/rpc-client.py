#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Exercise Lean RPC wrappers through HttpCurl and the real recording responder."""
import base64
from contextlib import contextmanager
from decimal import Decimal
import importlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

from cases import APP, ROOT
import network

G = importlib.import_module("generate-rpc-recordings")
R = importlib.import_module("rpc-recordings")
EXE = APP / ".lake/build/bin/CyberkrillTests"


def run(args, payload=None, *, cwd=APP):
    result = subprocess.run([str(EXE), *args], cwd=cwd, input=payload,
                            stdin=subprocess.DEVNULL if payload is None else None,
                            capture_output=True, timeout=45)
    assert result.returncode == 0, "Lean RPC test: " + result.stderr.decode()
    assert result.stderr == b"", "RPC success stderr"
    return result.stdout.decode()


@contextmanager
def responder(path, *, delay_ms=0):
    directory = APP / ".lake/rpc-replay"
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as root:
        root = Path(root)
        log = root / "requests.jsonl"
        with (root / "stderr").open("wb") as errors:
            script = ROOT / "packages/http-curl/test/responder.py"
            args = [sys.executable, "-B", str(script), str(path), "--log", str(log)]
            if delay_ms:
                # Delay the real responder's selected reply. Parsing, selection,
                # logging, HTTP framing and the client transport remain real.
                program = """import importlib.util, sys, time
spec = importlib.util.spec_from_file_location('delayed_rpc_responder', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
delay = int(sys.argv[2])
original = module.Handler.send_recorded
def delayed(self, response):
    time.sleep(delay / 1000)
    original(self, response)
module.Handler.send_recorded = delayed
sys.argv = [sys.argv[1], *sys.argv[3:]]
module.main()
"""
                args = [sys.executable, "-B", "-c", program, str(script), str(delay_ms),
                        str(path), "--log", str(log)]
            child = subprocess.Popen(args, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=errors)
            old = {}
            def interrupted(signum, _frame): raise InterruptedError("RPC replay interrupted")
            try:
                for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]:
                    old[sig] = signal.signal(sig, interrupted)
                assert select.select([child.stdout], [], [], 10)[0], "RPC responder startup deadline"
                ready = child.stdout.readline().decode().split()
                assert len(ready) == 3 and ready[0] == "READY", "RPC responder READY"
                port = int(ready[1])
                assert 0 < port < 65536 and port != 8332, "RPC explicit ephemeral port"
                yield "http://127.0.0.1:" + str(port), log, int(ready[2])
            finally:
                for sig in old: signal.signal(sig, signal.SIG_IGN)
                try:
                    child.stdin.close()
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)
                    child.stdout.close()
                    assert child.returncode == 0, "RPC responder reaped"
                finally:
                    for sig, handler in old.items(): signal.signal(sig, handler)


def request(url, method, params, *, cwd=APP, **auth):
    payload = G.json_text(dict(url=url, method=method, params=params, **auth)).encode()
    return R.parse_json(run(["--rpc-request"], payload, cwd=cwd))


def logged(log): return [R.parse_json(line) for line in log.read_bytes().splitlines()]


def assert_request(row, entry, params):
    assert row["method"] == "POST" and row["path"] == entry["path"], "RPC HTTP verb/wallet endpoint"
    body = R.parse_json(row["body"])
    assert set(body) == {"jsonrpc", "id", "method", "params"}, "RPC envelope fields"
    assert body["jsonrpc"] == "2.0" and body["id"] == "cyberkrill", "RPC version/id"
    assert body["method"] == entry["rpc"]["method"], "RPC wrapper method"
    assert G.selector(body["params"]) == G.selector(params), "RPC exact wrapper params/order/options"


def replay():
    counts = []
    methods = set()
    for definition in G.inventory():
        path = G.HERE / "recordings" / definition["recording"]
        data = R.parse_json(path.read_bytes())
        with responder(path) as (base, log, _):
            url = base + data["entries"][0]["path"]
            output = run(["--rpc-replay", url, str(path)])
            expected = [(entry, params) for entry in data["entries"] for params in entry["rpc"]["params"] for _ in entry["responses"]]
            records = logged(log)
            assert len(records) == len(expected), "RPC case-local wrapper request completeness"
            assert output == f"RPC wrapper responses: {len(expected)}\n", "RPC Lean wrapper inventory"
            for observed, (entry, params) in zip(records, expected):
                assert_request(observed, entry, params)
                methods.add(entry["rpc"]["method"])
            counts.append(len(expected))
        print(f"Lean RPC {definition['name']}: {len(expected)} recorded responses", flush=True)
    assert counts == [10, 10, 9, 15, 13, 5, 2, 11], "RPC wrapper response inventory"
    assert methods == R.METHODS and sum(counts) == 75, "RPC eleven-wrapper inventory"
    print("Lean RPC wrappers: 11/11; case-local responses: 75/75; exact requests checked", flush=True)


def continuation():
    path = G.HERE / "recordings/multipath-create.json"
    data = R.parse_json(path.read_bytes())
    with responder(path) as (base, log, _):
        run(["--rpc-continuation", base + "/wallet/single", str(path)])
        expected = [e for e in data["entries"] if e["rpc"]["method"] != "createpsbt"]
        rows = logged(log)
        assert len(rows) == len(expected) == 8, "RPC ignored import subsequent request count"
        for row, entry in zip(rows, expected): assert_request(row, entry, entry["rpc"]["params"][0])
    print("Lean RPC ignored import: 1/1; 8/8 subsequent wrapper requests", flush=True)


def continuation_failure():
    path = G.HERE / "recordings/multipath-create.json"
    data = R.parse_json(path.read_bytes())
    with responder(path) as (base, log, _):
        run(["--rpc-continuation-auth", base + "/wallet/single", str(path)])
        entries = [e for e in data["entries"] if e["rpc"]["method"] == "getdescriptorinfo"][:2]
        records = logged(log)
        assert len(records) == 2, "RPC helper failure actual requests"
        for record, entry in zip(records, entries): assert_request(record, entry, entry["rpc"]["params"][0])
    print("Lean RPC descriptor helper preserves HTTP failure: 1/1", flush=True)


def authentication(only=None):
    path = G.HERE / "recordings/single-list.json"
    first = R.parse_json(path.read_bytes())["entries"][0]
    method, params = first["rpc"]["method"], first["rpc"]["params"][0]
    parent = APP / ".lake/rpc-auth"
    parent.mkdir(parents=True, exist_ok=True)
    cases = [
        ("neither", None, {}, False), ("user-only", None, dict(user="lck"), False),
        ("password-only", None, dict(password="lck-throwaway"), False),
        ("pair", None, dict(user="lck", password="lck-throwaway"), True),
        ("wrong-password", None, dict(user="lck", password="wrong-password-sentinel"), False),
        ("cookie", b"lck:lck-throwaway", {}, True),
        ("cookie-trim", b"  lck:lck-throwaway\n", {}, True),
        ("cookie-preference", b"lck:lck-throwaway", dict(user="wrong", password="wrong"), True),
        ("empty-directory", b"lck:lck-throwaway", dict(user="wrong", password="wrong"), True),
        ("wrong-cookie", b"lck:wrong-cookie-sentinel", {}, False),
        ("missing-fallback", None, dict(user="lck", password="lck-throwaway"), True),
        ("malformed-fallback", b"malformed-cookie-sentinel", dict(user="lck", password="lck-throwaway"), True),
        ("unreadable-fallback", "directory", dict(user="lck", password="lck-throwaway"), True),
        ("missing-no-pair", None, dict(user="lck"), False),
        ("malformed-no-pair", b"malformed-cookie-sentinel", {}, False),
        ("unreadable-no-pair", "directory", {}, False),
        ("first-colon-password", b"lck:lck-throwaway:extra", {}, False),
        ("empty-pair", None, dict(user="", password=""), False)]
    for name, cookie, auth, success in cases:
        if only is not None and only != name: continue
        with tempfile.TemporaryDirectory(dir=parent) as directory, responder(path) as (base, log, _):
            cookie_path = Path(directory) / ".cookie"
            if cookie == "directory": cookie_path.mkdir()
            elif cookie is not None: cookie_path.write_bytes(cookie)
            use_dir = cookie is not None or name.startswith("missing")
            explicit = "" if name == "empty-directory" else directory
            result = request(base + first["path"], method, params, cwd=directory, **auth,
                             **(dict(dir=explicit) if use_dir else {}))
            if success: assert G.selector(result.get("result")) == G.selector(R.result(first)), "RPC auth resolution " + name
            else: assert result.get("error") == "rpcHttp: HTTP 401", "RPC recorded 401 " + name
            rows = logged(log)
            assert len(rows) == 1, "RPC auth request count"
            assert_request(rows[0], first, params)
    assert len(cases) == 18, "RPC auth case inventory"
    assert only is None or only in {r[0] for r in cases}, "RPC selected auth case"
    print("Lean RPC auth resolution/recorded 401: " + ("18/18" if only is None else only), flush=True)


def synthetic():
    # These envelopes are authored transport/error fixtures, never Core captures.
    secrets = ["cookie-user-sentinel:cookie-password-sentinel", "password-bytes-sentinel",
               "Basic " + base64.b64encode(b"synthetic:password-bytes-sentinel").decode()]
    echo = "|".join(secrets)
    rows = [
        ("omitted-error", 200, '{"result":7}', dict(result=Decimal(7))),
        ("null-result", 200, '{"result":null,"error":null}', dict(result=None)),
        ("malformed", 200, echo, dict(error="rpcMalformed: invalid JSON response")),
        ("missing", 200, '{"untrusted":"' + echo + '"}', dict(error="rpcMissingResult: response has no result")),
        ("rpc", 200, '{"error":{"code":-99,"message":"' + echo + '"}}', dict(error="rpcError: Core rejected the request")),
        ("http-before-json", 503, echo, dict(error="rpcHttp: HTTP 503")),
        ("http-before-rpc", 401, '{"error":{"message":"' + echo + '"}}', dict(error="rpcHttp: HTTP 401")),
        ("non-object", 200, '["' + echo + '"]', dict(error="rpcMalformed: invalid JSON response"))]
    directory = APP / ".lake/rpc-synthetic"
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as root:
        fixture = Path(root) / "synthetic.json"
        entries = [dict(method="POST", path="/" + name, rpc=dict(method="synthetic", params=[[]]),
                        responses=[dict(status=status, text=body)]) for name, status, body, _ in rows]
        fixture.write_text(json.dumps(dict(entries=entries)))
        with responder(fixture) as (base, log, closed):
            for (name, _, _, expected), entry in zip(rows, entries):
                result = request(base + "/" + name, "synthetic", [], user="synthetic", password=secrets[1])
                assert all(s not in G.json_text(result) for s in secrets), "RPC secret suppression " + name
                for key, value in expected.items(): assert result.get(key) == value and key in result, "RPC synthetic " + name
            transport = request("http://127.0.0.1:" + str(closed), "synthetic", [])
            assert transport["error"] == "rpcTransport: HTTP transport failed", "RPC transport failure class"
            records = logged(log)
            assert len(records) == 8, "RPC synthetic response inventory"
            for record, entry in zip(records, entries): assert_request(record, entry, [])
    print("Lean RPC synthetic envelopes/precedence/secrets: 8/8; transport: 1/1", flush=True)


def precision():
    amounts = [Decimal("1e-11"), Decimal("0.0000000000100"), Decimal("1.23456789012"),
               Decimal("9007199254740993"), Decimal("18446744073709551617e-11"),
               Decimal("1e3"), Decimal("-1"), Decimal("1e-12"), Decimal("0.0000000000010"), Decimal("0e-20")]
    expected = [1, 1, 123456789012, 900719925474099300000000000, 18446744073709551617,
                100000000000000, None, None, None, 0]
    parent = APP / ".lake/rpc-precision"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        fixture = Path(directory) / "synthetic.json"
        entries = [dict(method="POST", path="/incoming/" + str(i), rpc=dict(method="getreceivedbyaddress", params=[["synthetic", 7]]),
                        responses=[dict(status=200, text=G.json_text(dict(result=value)))]) for i, value in enumerate(amounts)]
        accepted = [a for a, value in zip(amounts, expected) if value is not None]
        params = [[dict(txid="synthetic", vout=2, sequence=7)], {"synthetic-" + str(i): a for i, a in enumerate(accepted)}, 12, True]
        entries.append(dict(method="POST", path="/outgoing", rpc=dict(method="createpsbt", params=[params]),
                            responses=[dict(status=200, text='{"result":"synthetic-precision-psbt"}')]))
        zeros = [dict(values=[Decimal("0e-20"), Decimal("0e-11")])]
        entries.append(dict(method="POST", path="/generic-zero", rpc=dict(method="synthetic-zero", params=[zeros]),
                            responses=[dict(status=200, text='{"result":true}')]))
        fixture.write_text(G.json_text(dict(entries=entries)))
        with responder(fixture) as (base, log, _):
            for i, value in enumerate(expected):
                result = request(base + "/incoming/" + str(i), "unused", [], operation="received")
                if value is None: assert result["error"].startswith("rpcInvalidAmount:"), "RPC incoming sub-msat/negative refusal"
                else: assert result.get("msat") == value, "RPC HTTP incoming exact precision"
            result = request(base + "/outgoing", "unused", [], operation="create", amounts=accepted)
            assert result.get("result") == "synthetic-precision-psbt", "RPC HTTP outgoing numeric precision"
            result = request(base + "/generic-zero", "synthetic-zero", zeros)
            assert result.get("result") is True, "RPC generic exact zero serialization"
            records = logged(log)
            assert len(records) == 12, "RPC HTTP precision inventory"
            for record, entry in zip(records, entries): assert_request(record, entry, entry["rpc"]["params"][0])
    assert len(amounts) == 10 and len(accepted) == 7, "RPC numeric input/output inventory"
    print("Lean RPC HTTP precision: 10/10 incoming; 7/7 outgoing numeric values; optional sequence/locktime/replaceable", flush=True)


def timeouts(only=None):
    # A real scan response arrives after the default 30-second deadline. A
    # separately selected short-deadline case detects accidentally disabling it.
    rows = [("long", 60000, 31000), ("short", 50, 300)]
    assert only is None or only in {r[0] for r in rows}, "RPC timeout selection"
    directory = APP / ".lake/rpc-timeouts"
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as root:
        fixture = Path(root) / "synthetic.json"
        entry = dict(method="POST", path="/scan", rpc=dict(method="scantxoutset", params=[["start", []]]),
                     responses=[dict(status=200, json=dict(result=dict(success=True, height=1, unspents=[], total_amount=0)))])
        fixture.write_text(json.dumps(dict(entries=[entry])))
        for name, deadline, delay in rows:
            if only is not None and only != name: continue
            with responder(fixture, delay_ms=delay) as (base, log, _):
                started = time.monotonic()
                result = request(base + "/scan", "unused", [], operation="scan", totalTimeoutMs=deadline)
                elapsed = time.monotonic() - started
                if name == "long":
                    assert result == dict(success=True, height=1), "RPC configured long scan deadline"
                    assert elapsed >= 30, "RPC delayed scan crosses default deadline"
                else:
                    assert result.get("error") == "rpcTransport: HTTP transport failed", "RPC configured short scan deadline"
                    assert elapsed < 2, "RPC configured scan deadline remains bounded"
                records = logged(log)
                assert len(records) == 1, "RPC delayed scan request count"
                assert_request(records[0], entry, ["start", []])
    if only is None: print("Lean RPC scan deadlines: 2/2; delayed beyond default and bounded short override", flush=True)


def main():
    if not (network.sandbox() or network.isolated()):
        return network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])
    selected = sys.argv[1:]
    checks = dict(replay=replay, continuation=continuation, continuation_failure=continuation_failure,
                  auth=authentication, synthetic=synthetic, precision=precision, timeouts=timeouts)
    if selected:
        assert len(selected) == 1
        if selected[0].startswith("auth/"): authentication(selected[0][5:])
        elif selected[0].startswith("timeout/"): timeouts(selected[0][8:])
        else:
            assert selected[0] in checks
            checks[selected[0]]()
    else:
        print(run(["--rpc-pure"]), end="", flush=True)
        for check in checks.values(): check()
    return 0


if __name__ == "__main__": sys.exit(main())
