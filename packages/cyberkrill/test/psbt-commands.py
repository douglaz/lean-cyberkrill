#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Actual PSBT handlers, pinned offline captures and labeled synthetic controls."""
import base64
import copy
from decimal import Decimal
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from cases import APP, ROOT, PIN, BUILD
from compare import differences, exact_json
import network

C = importlib.import_module("rpc-client")
G, R = C.G, C.R
HERE = APP / "test"
EXE = APP / ".lake/build/bin/cyberkrill"
DEST = HERE / "golden/psbt-commands-reference.json"


def matrix():
    rows = []
    for inputs in ["descriptor", "explicit"]:
        for rate in [None, "1sat", "2.5sats", "0.00000001"]:
            rows.append(dict(name="create-" + inputs + "-" + str(rate), case="multipath-create", inputs=inputs, rate=rate))
    for name, extra in [("duplicate", dict(duplicate=True, rate="2.5sats")),
                        ("grammar", dict(grammar=True)), ("json", dict(json=True)),
                        ("raw", dict(raw=True)), ("both", dict(json=True, raw=True))]:
        rows.append(dict(name="create-" + name, case="multipath-create", inputs="descriptor", **extra))
    for name, case, rate in [("unit", "change-funded", "1sat"),
                             ("fractional", "funded-fractional", "2.5sats"),
                             ("bare", "change-funded", "0.00000001"),
                             ("both", "change-funded", "1sat")]:
        rows.append(dict(name="funded-" + name, case=case, inputs="descriptor", rate=rate,
                         json=name == "both", raw=name == "both"))
    assert len(rows) == 17, "PSBT capture matrix inventory"
    return rows


def data_for(row):
    return R.parse_json((HERE / ("recordings/" + row["case"] + ".json")).read_bytes())


def plan(row):
    data = data_for(row)
    final = data["entries"][-1]
    params = final["rpc"]["params"][0]
    funded = final["rpc"]["method"] == "walletcreatefundedpsbt"
    command = "onchain-create-funded-psbt" if funded else "onchain-create-psbt"
    args = [command, "--network", "regtest"]
    if row["inputs"] == "descriptor":
        inputs = [data["entries"][0]["rpc"]["params"][0][0]]
        requests = [[e["rpc"]["method"], e["rpc"]["params"][0]] for e in data["entries"]]
    else:
        inputs = [p["txid"] + ":+" + str(p["vout"]) for p in params[0]]
        requests = [[final["rpc"]["method"], params]]
    for index, value in enumerate(inputs):
        args += ["--inputs=" + value] if index % 2 else ["--inputs", " " + value + " "]
    address, amount = next(iter(params[1].items()))
    output = address + ":1000000sat"
    if row.get("duplicate"): output = address + ":2000000sat," + output
    if row.get("grammar"): output = "  " + address + " : 0.01  "
    args += ["--outputs", output]
    if row.get("rate") is not None: args += ["--fee-rate", row["rate"]]
    if row.get("json"): args += ["-ooutput.json"]
    if row.get("raw"): args += ["--psbt-output=raw.psbt"]
    result = R.result(final)
    if funded:
        expected = dict(psbt=result["psbt"], fee_sats=int(result["fee"] * Decimal(100000000)), change_position=result["changepos"])
    else:
        # Independent weight arithmetic, including CompactSize and witness marker.
        count = len(params[0])
        weight = 4 * (4 + 1 + 1 + 31 + 4) + count * (4 + (72 + 1 + 33 + 1 + 1) + 160) + 2
        rate = Decimal("2.5") if row.get("rate") == "2.5sats" else Decimal(1) if row.get("rate") else Decimal(0)
        fee = int((Decimal((weight + 3) // 4) * rate).to_integral_value(rounding="ROUND_HALF_UP"))
        expected = dict(psbt=result, fee_sats=fee, change_position=None)
    return args, requests, expected


def observed(log):
    return [[R.parse_json(r["body"])["method"], R.parse_json(r["body"])["params"]] for r in C.logged(log)]


def same(left, right, label):
    assert G.selector(left) == G.selector(right), "PSBT " + label


def one(row, reference=None):
    args, requests, expected = plan(row)
    path = HERE / ("recordings/" + row["case"] + ".json")
    parent = APP / ".lake/validation/psbt-replay"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory)
        with C.responder(path) as (base, log, _):
            args += ["--rpc-url", base + "/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"]
            env = dict(os.environ, HOME=str(root))
            if reference:
                result = G.run([str(reference), *args], stub_url=base, reference=True,
                               cwd=root, env=env, timeout=30, check=False)
            else:
                result = network.checked_run(EXE, args, stub_url=base, cwd=root, env=env,
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            actual = observed(log)
            bare = row.get("rate") == "0.00000001" and reference is None
            if bare:
                assert result.returncode == 1 and result.stdout == b"" and result.stderr == b"feeUnitRequired: Specify a Bitcoin unit, for example 15sats\n", "PSBT actual bare fee refusal"
                same(actual, [], "bare fee zero connection")
            else:
                assert result.returncode == 0 and result.stderr == b"", "PSBT CLI success " + row["name"] + ": " + result.stderr.decode()
                output = (root / "output.json").read_bytes() if row.get("json") else result.stdout
                assert bool(output) and not output.endswith(b"\n"), "PSBT JSON no newline"
                same(R.parse_json(output), expected, "full JSON/null/fee shape " + row["name"])
                assert (result.stdout == b"") == bool(row.get("json")), "PSBT stdout/file destinations"
                if row.get("raw"): assert (root / "raw.psbt").read_bytes() == expected["psbt"].encode(), "PSBT raw bytes no newline"
                same(actual, requests, "actual ordered exact params " + row["name"])
                assert all(r["path"] == "/wallet/single" for r in C.logged(log)), "PSBT wallet paths"
            return dict(name=row["name"], status=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode(),
                        files={p: (root / p).read_text() if (root / p).exists() else None for p in ["output.json", "raw.psbt"]},
                        requests=G.json_text(actual))


def entry(method, params, result=None, error=None):
    body = dict(result=result, error=error)
    return dict(method="POST", path="/synthetic", rpc=dict(method=method, params=[params]),
                responses=[dict(status=200, json=body)])


def synthetic(only=None):
    data = data_for(matrix()[0]); original = data["entries"][-1]
    params = original["rpc"]["params"][0]; psbt = R.result(original)
    inputs, outputs = params[:2]
    outargs = ["--outputs", next(iter(outputs)) + ":1000000sat"]
    inargs = sum((["--inputs", p["txid"] + ":" + str(p["vout"])] for p in inputs), [])
    parent = APP / ".lake/validation/psbt-controls"; parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); fixture = root / "synthetic.json"
        for name, result, options, expected in [
            ("defaults", dict(psbt=psbt), [], (0, -1)),
            ("nonnumeric", dict(psbt=psbt, fee="private-sentinel", changepos=False), [], (0, -1)),
            ("position-wrap", dict(psbt=psbt, fee=Decimal("0.00000001"), changepos=4294967295), [], (1, -1)),
            ("options", dict(psbt=psbt, fee=Decimal("0.00000001"), changepos=0),
             ["--conf-target", "+4294967295", "--estimate-mode", "arbitrary", "--fee-rate", "2.5sats"], (1, 0))]:
            if only and only != name: continue
            expected_params = [inputs, outputs, 0]
            if options: expected_params.append(dict(conf_target=4294967295, estimate_mode="arbitrary", fee_rate=Decimal("2.5")))
            fixture.write_text(G.json_text(dict(entries=[entry("walletcreatefundedpsbt", expected_params, result)])))
            with C.responder(fixture) as (base, log, _):
                args = ["onchain-create-funded-psbt", *inargs, *outargs, *options, "--rpc-url", base + "/synthetic"]
                proc = network.checked_run(EXE, args, stub_url=base, cwd=root, capture_output=True, timeout=15)
                assert proc.returncode == 0 and proc.stderr == b"", "PSBT synthetic " + name
                value = R.parse_json(proc.stdout)
                same([value["fee_sats"], value["change_position"]], list(expected), "synthetic defaults/conversion " + name)
                same(observed(log), [["walletcreatefundedpsbt", expected_params]], "synthetic options omission/no probe " + name)
                count += 1
        for name, corrupt in [("base64", "!"), ("magic", base64.b64encode(b"wrong").decode())]:
            if only and only != name: continue
            fixture.write_text(G.json_text(dict(entries=[entry("createpsbt", params, corrupt)])))
            with C.responder(fixture) as (base, log, _):
                args = ["onchain-create-psbt", *inargs, *outargs, "--rpc-url", base + "/synthetic", "-o", "out.json", "--psbt-output", "raw.psbt"]
                proc = network.checked_run(EXE, args, stub_url=base, cwd=root, capture_output=True, timeout=15)
                assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.startswith(b"psbt"), "PSBT validation " + name
                assert (root / "out.json").read_bytes() == b"" and not (root / "raw.psbt").exists(), "PSBT validate before writes"
                count += 1
    if only is None: assert count == 6, "PSBT synthetic default/validation inventory"
    print(f"PSBT synthetic defaults/options/framing: {count} checks", flush=True)


def refusals():
    count = 0
    parent = APP / ".lake/validation/psbt-refusals"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory)
        with C.responder(HERE / "recordings/multipath-create.json") as (base, log, _):
            for command in ["onchain-create-psbt", "onchain-create-funded-psbt"]:
                common = [command, "--inputs", "synthetic:0", "--outputs", "destination:1sat", "--rpc-url", base]
                for extra, error, parse in [(["--network", "bad"], "invalidNetwork", False),
                    (["--wallet-file", "unread"], "unsupportedWalletFile", False),
                    (["--wallet-file", "unread", "--bitcoin-dir", "unused"], "unsupportedWalletFile", False),
                    (["--descriptor", "ignored", "--bitcoin-dir", "unused"], "unsupportedBackend", False),
                    (["--bitcoin-dir", "unused", "--rpc-user", "sentinel"], "rpcFlagConflict", True),
                    (["--electrum", "unused"], "invalidArguments", True),
                    (["--esplora", "unused"], "invalidArguments", True)]:
                    output = root / "output"; output.write_text("sentinel")
                    proc = network.checked_run(EXE, common + ["-o", str(output), *extra], stub_url=base, cwd=root, capture_output=True, timeout=10)
                    assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.decode().startswith(error + ":"), "PSBT refusal " + error
                    assert output.read_bytes() == (b"sentinel" if parse else b""), "PSBT truncation/refusal timing"
                    count += 1
                for output, error in [("", "invalidOutputs"), ("destination:1sat,", "invalidOutputs"),
                    (",destination:1sat", "invalidOutputs"), ("destination", "invalidOutputs"),
                    (":1sat", "invalidOutputs"), ("destination:1msat", "wholeSatRequired"),
                    ("destination:1msat,broken", "invalidOutputs")]:
                    args = [command, "--inputs", "synthetic:0", "--outputs", output, "--rpc-url", base]
                    proc = network.checked_run(EXE, args, stub_url=base, cwd=root, capture_output=True, timeout=10)
                    assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.decode().startswith(error + ":"), "PSBT output grammar/precedence"
                    count += 1
                for extra in [["--fee-rate", "broken"], ["--fee-rate=0.00000001"]]:
                    for args, status in [(common + extra + ["--help"], 1), ([command, "--rpc-url", base, "--help"] + extra, 0)]:
                        proc = network.checked_run(EXE, args, stub_url=base, capture_output=True, timeout=10)
                        assert proc.returncode == status, "PSBT typed/help fee ordering"
                        count += 1
            for value in ["0", "+4294967295", "1009", "4294967296", "1_0", "++1", " 1"]:
                for before in [False, True]:
                    flags = ["--conf-target=" + value]
                    args = ["onchain-create-funded-psbt", "--rpc-url", base] + (["--help"] + flags if before else flags + ["--help"])
                    proc = network.checked_run(EXE, args, stub_url=base, capture_output=True, timeout=10)
                    valid = value in ["0", "+4294967295", "1009"]
                    assert proc.returncode == (0 if before or valid else 1), "PSBT conf target u32/help ordering"
                    count += 1
            assert observed(log) == [], "PSBT refusal zero connections"
    assert count == 50, "PSBT refusal inventory"
    print(f"PSBT CLI grammar/refusal/help: {count}/50; zero RPC", flush=True)


def field(key, value):
    assert len(key) < 253 and len(value) < 253, "PSBT test-only short field"
    return bytes([len(key)]) + key + bytes([len(value)]) + value


def numeric_cases():
    rows = [("plain-int", "1", None, 1), ("plain-negative", "-2", None, -2),
            ("float", "1.0", None, -1), ("exponent", "1e0", None, -1),
            ("negative-zero", "-0", None, -1), ("zero-exponent", "0e3", None, -1),
            ("i32-wrap", "4294967295", None, -1),
            ("i64-overflow", "9223372036854775808", None, -1),
            ("msat-fee", "0", "0.00000000001", None),
            ("fractional-sat-fee", "0", "0.0000000125", None),
            ("u64-fee-overflow", "0", "184467440737.09551616", None)]
    assert len(rows) == 11, "PSBT numeric control inventory"
    return rows


def numeric_one(row, reference=None):
    name, token, fee, expected_position = row
    original = data_for(matrix()[0])["entries"][-1]
    params = original["rpc"]["params"][0][:3]
    psbt = R.result(original)
    result = '{"psbt":' + json.dumps(psbt) + ',"changepos":' + token
    if fee is not None: result += ',"fee":' + fee
    body = '{"jsonrpc":"2.0","id":"cyberkrill","result":' + result + '},"error":null}'
    parent = APP / ".lake/validation/psbt-numeric"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); fixture = root / "synthetic.json"
        control = entry("walletcreatefundedpsbt", params)
        control["responses"] = [dict(status=200, text=body)]
        fixture.write_text(G.json_text(dict(entries=[control])))
        args = ["onchain-create-funded-psbt", "--network", "regtest"]
        for value in params[0]: args += ["--inputs", value["txid"]+":"+str(value["vout"])]
        args += ["--outputs", next(iter(params[1]))+":1000000sat", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"]
        with C.responder(fixture) as (base, log, _):
            args += ["--rpc-url", base+"/synthetic"]
            environment = dict(os.environ, HOME=str(root))
            if reference:
                proc = G.run([str(reference), *args], reference=True, stub_url=base,
                             cwd=root, env=environment, timeout=20, check=False)
            else:
                proc = network.checked_run(EXE, args, stub_url=base, cwd=root, env=environment,
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
            assert proc.returncode == (1 if expected_position is None else 0), "PSBT numeric status " + name
            if expected_position is not None:
                same(R.parse_json(proc.stdout), dict(psbt=psbt, fee_sats=0, change_position=expected_position), "numeric value " + name)
                assert proc.stderr == b"" and not proc.stdout.endswith(b"\n"), "PSBT numeric streams"
            else:
                assert proc.stdout == b"" and proc.stderr, "PSBT numeric rejection streams"
                if not reference:
                    error = b"invalidFee:" if name == "u64-fee-overflow" else b"wholeSatRequired:"
                    assert proc.stderr.startswith(error), "PSBT numeric rejection code " + name
            same(observed(log), [["walletcreatefundedpsbt", params]], "numeric one final request/no probe")
            return dict(name=name, kind="synthetic numeric default control; recorded PSBT only",
                        status=proc.returncode, stdout=proc.stdout.decode(), stderr=proc.stderr.decode())


def numeric(only=None):
    captures = json.loads(DEST.read_bytes())["synthetic_numeric_controls"]
    assert len(captures) == 11, "PSBT synthetic numeric capture inventory"
    for row, reference in zip(numeric_cases(), captures):
        if only and row[0] != only: continue
        actual = numeric_one(row)
        assert actual["name"] == reference["name"] and actual["status"] == reference["status"], "PSBT numeric capture identity/status"
        if actual["status"] == 0:
            same(R.parse_json(actual["stdout"]), R.parse_json(reference["stdout"]), "numeric reference JSON")
            assert actual["stderr"] == reference["stderr"] == "", "PSBT numeric independent stderr"
        else: assert reference["stdout"] == "" and reference["stderr"], "PSBT numeric reference rejection"
    print("PSBT synthetic numeric defaults: " + (only or "11/11 pinned controls"), flush=True)


def exact_cases():
    return [(command+"-"+kind, command, kind) for kind in ["rounded", "wire"] for command in ["create", "funded"]] + [
        ("funded-negative-probe", "funded", "negative-probe"),
        ("funded-tiny-probe", "funded", "tiny-probe")]


def exact_one(row, reference=None):
    name, command, kind = row
    funded = command == "funded"
    source = next(r for r in matrix() if r["name"] == ("funded-unit" if funded else "create-descriptor-1sat"))
    args, requests, expected = plan(source)
    data = data_for(source)
    parent = APP/".lake/validation/psbt-exact"; parent.mkdir(parents=True, exist_ok=True)
    amount = {"rounded": "1000000.0004sat", "wire": "20999999.9769"}.get(kind, "1000000sat")
    args[args.index("--outputs")+1] = next(iter(requests[-1][1][1]))+":"+amount
    if kind == "rounded":
        wanted = requests if reference else []
        error = "subMillisatoshi: Amount has sub-msat precision\n"
    elif kind == "wire":
        # The transport refusal is synthetic, with public outpoints. No Core
        # success or PSBT corresponding to this altered output is claimed.
        explicit = requests[-1][1][0]
        args = [args[0], "--network", "regtest", "--outputs", args[args.index("--outputs")+1], "--fee-rate", "1sat"]
        for value in explicit: args += ["--inputs", value["txid"]+":"+str(value["vout"])]
        params = [explicit, {next(iter(requests[-1][1][1])): Decimal("20999999.9769")}, 0]
        if funded: params.append(dict(fee_rate=1))
        else: params.append(False)
        control = entry(requests[-1][0], params, error=dict(code=-99, message="synthetic exact-wire refusal"))
        control["path"] = "/wallet/single"; data = dict(entries=[control])
        wanted = [] if reference else [[requests[-1][0], params]]
        error = "rpcError: Core rejected the request\n"
    else:
        token = Decimal(-1) if kind == "negative-probe" else Decimal("1e-12")
        data["entries"][10]["responses"] = [dict(status=200, json=dict(result=token, error=None))]
        if kind == "negative-probe":
            address = requests[10][1][0]
            requests[-1][1][3]["changeAddress"] = address
            data["entries"][-1]["rpc"]["params"][0][3]["changeAddress"] = address
            wanted = requests[:11]+[requests[-1]] if reference else requests[:11]
        else: wanted = requests if reference else requests[:11]
        data["entries"][-1]["responses"] = [dict(status=200, json=dict(result=None, error=dict(code=-99, message="synthetic probe final refusal")))]
        error = "rpcInvalidAmount: expected nonnegative exact millisatoshis\n"
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); fixture = root/"synthetic.json"
        fixture.write_text(G.json_text(data))
        path = HERE/("recordings/"+source["case"]+".json") if kind == "rounded" else fixture
        with C.responder(path) as (base, log, _):
            args += ["--rpc-url", base+"/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"]
            env = dict(os.environ, HOME=str(root))
            if reference:
                proc = G.run([str(reference), *args], reference=True, stub_url=base, cwd=root, env=env, timeout=30, check=False)
            else:
                proc = network.checked_run(EXE, args, stub_url=base, cwd=root, env=env, capture_output=True, timeout=30)
            calls = observed(log)
            same(calls, wanted, "precise exact requests/stopping " + name)
            if reference and kind == "rounded":
                assert proc.returncode == 0 and proc.stderr == b"", "PSBT rounded reference success"
                same(R.parse_json(proc.stdout), expected, "rounded reference complete recorded result")
            else:
                assert proc.returncode == 1 and proc.stdout == b"", "PSBT exact exception status " + name
                if not reference: assert proc.stderr.decode() == error, "PSBT exact exception error " + name + ": " + proc.stderr.decode()
                elif kind == "wire": assert b"whole number of satoshis" in proc.stderr, "PSBT exact wire reference precision refusal"
                else: assert b"synthetic probe final refusal" in proc.stderr, "PSBT reference probe reaches final refusal"
            return dict(name=name, command=args[0], kind="unchanged recorded replies" if kind == "rounded" else "synthetic transport control; public recorded inputs only",
                        input_amount=amount, probe_number="-1" if kind == "negative-probe" else "1e-12" if kind == "tiny-probe" else None,
                        status=proc.returncode, stdout=proc.stdout.decode(), stderr=proc.stderr.decode(), requests=G.json_text(calls))


def exact(only=None):
    provenance = json.loads((HERE/"psbt-commands-provenance.json").read_bytes())
    assert hashlib.sha256(DEST.read_bytes()).hexdigest() == provenance["capture_sha256"], "PSBT precise capture bytes/status/error/value pin"
    captures = json.loads(DEST.read_bytes())["exact_amount_exceptions"]
    assert [c["name"] for c in captures] == [r[0] for r in exact_cases()], "PSBT precise exception identities/unused entries"
    for row, reference in zip(exact_cases(), captures):
        if only and row[0] != only: continue
        actual = exact_one(row)
        for key in ["name", "command", "kind", "input_amount", "probe_number"]:
            assert actual[key] == reference[key], "PSBT precise exception identity/value " + key
        assert reference["status"] == (0 if row[2] == "rounded" else 1), "PSBT precise reference status"
        if row[2] == "rounded":
            assert reference["stderr"] == "" and reference["stdout"], "PSBT precise rounded streams"
        else: assert reference["stdout"] == "" and reference["stderr"], "PSBT precise reference refusal streams"
        # Independently pin full reference request values, order and results too.
        if row[2] == "rounded":
            source = next(r for r in matrix() if r["name"] == ("funded-unit" if row[1] == "funded" else "create-descriptor-1sat"))
            _, requests, expected = plan(source)
            same(R.parse_json(reference["requests"]), requests, "rounded full reference requests")
            same(R.parse_json(reference["stdout"]), expected, "rounded full reference result")
        else:
            calls = R.parse_json(reference["requests"])
            if row[2] == "wire":
                source = next(r for r in matrix() if r["name"] == ("funded-unit" if row[1] == "funded" else "create-descriptor-1sat"))
                address = next(iter(plan(source)[1][-1][1][1]))
                same(calls, [], "precise reference zero wire requests")
                assert reference["stderr"] == f"Error: On-chain output amount '20999999.9769' in output '{address}:20999999.9769' must be a whole number of satoshis; got 2099999997690000.25 sats\n", "PSBT precise reference wire error/value"
            else:
                source = next(r for r in matrix() if r["name"] == "funded-unit")
                requests = plan(source)[1]
                if row[2] == "negative-probe":
                    requests[-1][1][3]["changeAddress"] = requests[10][1][0]
                    requests = requests[:11]+[requests[-1]]
                same(calls, requests, "precise reference complete probe scanning/stopping")
                assert reference["stderr"] == 'Error: RPC error: {"code":-99,"message":"synthetic probe final refusal"}\n', "PSBT precise reference probe error"
        assert set(actual) == set(reference), "PSBT precise exception unused fields"
    print("PSBT precise exact-amount exceptions: 6/6; 2 recorded-handler rounding captures; 4 separate synthetic transport/probe captures; exact wire and stopping checked", flush=True)


def maps(raw):
    def number(i):
        first = raw[i]; i += 1
        width = {253: 2, 254: 4, 255: 8}.get(first, 0)
        return (int.from_bytes(raw[i:i+width], "little"), i+width) if width else (first, i)
    i = 5; result = []
    while i < len(raw):
        records = []
        while raw[i] != 0:
            start = i; size, i = number(i); key = raw[i:i+size]; i += size
            size, i = number(i); value = raw[i:i+size]; i += size
            records.append((key, value, start))
        result.append((records, i)); i += 1
    return result


def spelling(only=None):
    """Test-only spelling mutations of recorded PSBTs, before either write."""
    count = 0
    parent = APP / ".lake/validation/psbt-spelling"; parent.mkdir(parents=True, exist_ok=True)
    for funded in [False, True]:
        if only and only.startswith(("create-", "funded-")) and only.split("-", 1)[0] != ("funded" if funded else "create"): continue
        row = next(r for r in matrix() if r["name"] == ("funded-unit" if funded else "create-explicit-1sat"))
        args, requests, expected = plan(row)
        final = data_for(row)["entries"][-1]
        # Explicit public outpoints isolate result validation from expansion.
        args = [args[0], "--network", "regtest", "--outputs", next(iter(requests[-1][1][1]))+":1000000sat"]
        for value in requests[-1][1][0]: args += ["--inputs", value["txid"]+":"+str(value["vout"])]
        params = requests[-1][1][:3] if funded else requests[-1][1]
        for name, prefix, suffix in [("valid", "", ""), ("newline", "", "\n"),
                                     ("space", " ", ""), ("tab", "", "\t"),
                                     ("crlf", "\r\n", "\r\n"), ("unicode", "\u00a0", "")]:
            if only and name != only.removeprefix("create-").removeprefix("funded-"): continue
            for existing in [False, True]:
                with tempfile.TemporaryDirectory(dir=parent) as directory:
                    root = Path(directory); fixture = root/"synthetic.json"
                    psbt = prefix+expected["psbt"]+suffix
                    result = dict(psbt=psbt) if funded else psbt
                    fixture.write_text(G.json_text(dict(entries=[entry(final["rpc"]["method"], params, result)])))
                    (root/"out.json").write_bytes(b"truncate-sentinel")
                    if existing: (root/"raw.psbt").write_bytes(b"preserve-sentinel")
                    with C.responder(fixture) as (base, log, _):
                        proc = network.checked_run(EXE, args+["--rpc-url", base+"/synthetic", "-o", "out.json", "--psbt-output", "raw.psbt"],
                            stub_url=base, cwd=root, capture_output=True, timeout=15)
                        assert proc.stdout == b"", "PSBT spelling empty stdout"
                        if name == "valid":
                            assert proc.returncode == 0 and proc.stderr == b"", "PSBT spelling valid success"
                            assert (root/"raw.psbt").read_bytes() == psbt.encode(), "PSBT spelling valid raw bytes"
                        else:
                            assert proc.returncode == 1 and proc.stderr.startswith(b"psbtBase64:"), "PSBT original spelling rejection " + name
                            assert (root/"out.json").read_bytes() == b"", "PSBT spelling early JSON truncation"
                            assert (root/"raw.psbt").read_bytes() == b"preserve-sentinel" if existing else not (root/"raw.psbt").exists(), "PSBT spelling validation before raw creation/overwrite"
                        same(observed(log), [[final["rpc"]["method"], params]], "spelling single result validation")
                        count += 1
    if only is None: assert count == 24, "PSBT spelling inventory"
    print(f"PSBT original RPC spelling: {count} recorded-PSBT derivatives; both handlers; raw creation/overwrite guarded", flush=True)


def deep_validation(only=None):
    """Only test-time mutations of the actual recorded PSBT; no other fixture."""
    source = data_for(matrix()[0])["entries"][-1]
    raw = base64.b64decode(R.result(source)); boundary = maps(raw)[1][1]
    funded = data_for(next(r for r in matrix() if r["name"] == "funded-unit"))["entries"][-1]
    records = maps(base64.b64decode(R.result(funded)["psbt"]))[1][0]
    key, value, _ = next(r for r in records if r[0][0] == 6)
    compressed = key[1:]; x = int.from_bytes(compressed[1:], "big"); prime = 2**256 - 2**32 - 977
    y = pow((x**3+7) % prime, (prime+1)//4, prime)
    if y % 2 != compressed[0] % 2: y = prime-y
    uncompressed = b"\x04" + compressed[1:] + y.to_bytes(32, "big")
    controls = [
        ("curve", field(b"\x06\x02" + b"\xff"*32, value), "psbtInvalidKey"),
        ("hash", field(b"\x0b" + b"\x00"*32, b"synthetic"), "psbtInvalidValue"),
        ("same-point", field(key, value) + field(b"\x06" + uncompressed, value), "psbtDuplicatePoint")]
    parent = APP / ".lake/validation/psbt-deep"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); fixture = root / "synthetic.json"
        params = source["rpc"]["params"][0]
        inargs = sum((["--inputs", p["txid"]+":"+str(p["vout"])] for p in params[0]), [])
        for name, added, error in controls:
            if only and name != only: continue
            corrupt = base64.b64encode(raw[:boundary] + added + raw[boundary:]).decode()
            fixture.write_text(G.json_text(dict(entries=[entry("createpsbt", params, corrupt)])))
            with C.responder(fixture) as (base, log, _):
                proc = network.checked_run(EXE, ["onchain-create-psbt", *inargs, "--outputs", next(iter(params[1]))+":1000000sat", "--rpc-url", base+"/synthetic"], stub_url=base, capture_output=True, timeout=10)
                assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.decode().startswith(error), "PSBT full validation " + name
                same(observed(log), [["createpsbt", params]], "deep validation reaches real handler")
    print("PSBT full validation: " + (only or "3/3 curve/hash/same-point recorded derivatives"), flush=True)


def probes(only=None):
    original = data_for(next(r for r in matrix() if r["name"] == "funded-unit"))
    args, requests, expected = plan(next(r for r in matrix() if r["name"] == "funded-unit"))
    tests = ["fallback", "fallback-error", "received-default", "list-default", "failed-derivation", "bound", "empty-expansion", "scope-dedup"]
    parent = APP / ".lake/validation/psbt-probes"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        fixture = Path(directory) / "synthetic.json"
        for name in tests:
            if only and only != name: continue
            data = copy.deepcopy(original); entries = data["entries"]
            wanted = copy.deepcopy(requests); success = True
            def set_result(e, value): e["responses"] = [dict(status=200, json=dict(result=value, error=None))]
            def fail(e): e["responses"] = [dict(status=200, json=dict(result=None, error=dict(code=-99, message="private-sentinel")))]
            if name in ["fallback", "fallback-error", "list-default"]:
                probe = entries[10]; fail(probe)
                address = wanted[10][1][0]
                control = entry("listunspent", [0, 9999999, [address]], [{}] if name != "list-default" else {})
                control["path"] = "/wallet/single"
                if name == "fallback-error": fail(control); wanted = wanted[:11]; success = False
                elif name == "list-default":
                    # The nonarray fallback is false and therefore selects address 0.
                    wanted = wanted[:11] + [wanted[-1]]
                    wanted[-1][1][3]["changeAddress"] = address
                    entries[-1]["rpc"]["params"][0][3]["changeAddress"] = address
                wanted.insert(11, ["listunspent", control["rpc"]["params"][0]])
                entries.append(control)
            elif name == "received-default":
                set_result(entries[10], "not numeric")
                address = wanted[10][1][0]
                wanted = wanted[:11] + [wanted[-1]]
                wanted[-1][1][3]["changeAddress"] = address
                entries[-1]["rpc"]["params"][0][3]["changeAddress"] = address
            elif name == "failed-derivation":
                fail(entries[8]); wanted = wanted[:9] + wanted[11:]
            elif name == "bound":
                # All 200 derivations fail; none of the derive/received calls run.
                descriptor = args[args.index("--inputs")+1].strip().replace("<0;1>", "1", 1)
                entries = entries[:8]
                wanted = wanted[:8]
                for index in range(200):
                    params = [descriptor.replace("*", str(index)).split("#", 1)[0]]
                    control = entry("getdescriptorinfo", params, error=dict(code=-99, message="synthetic"))
                    control["path"] = "/wallet/single"; entries.append(control)
                    wanted.append(["getdescriptorinfo", params])
                final = copy.deepcopy(original["entries"][-1]); del final["rpc"]["params"][0][3]["changeAddress"]
                entries.append(final); wanted.append(["walletcreatefundedpsbt", final["rpc"]["params"][0]])
            elif name == "empty-expansion":
                for index in [4, 7]: set_result(entries[index], [])
                wanted = wanted[:8]; success = False
            elif name == "scope-dedup":
                # Explicit duplicates and two descriptor invocations survive;
                # only duplicate outpoints within a descriptor call collapse.
                first = R.result(entries[4])[0]
                for index in [4, 7]: set_result(entries[index], [first, first])
                descriptor = args[args.index("--inputs")+1]
                chosen = dict(txid=first["txid"], vout=first["vout"])
                runargs = ["onchain-create-psbt", "--inputs", chosen["txid"]+":"+str(chosen["vout"]), "--inputs", descriptor, "--inputs", descriptor, "--outputs", next(iter(wanted[-1][1][1]))+":1000000sat"]
                entries = entries[:8]
                for e in entries: e["responses"] = e["responses"] * 2
                finalparams = [[chosen, chosen, chosen], wanted[-1][1][1], 0, False]
                control = entry("createpsbt", finalparams, error=dict(code=-99, message="synthetic")); control["path"] = "/wallet/single"; entries.append(control)
                wanted = wanted[:8] * 2 + [["createpsbt", finalparams]]; success = False
            data["entries"] = entries; fixture.write_text(G.json_text(data))
            with C.responder(fixture) as (base, log, _):
                proc = network.checked_run(EXE, (runargs if name == "scope-dedup" else args) + ["--rpc-url", base+"/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"], stub_url=base, capture_output=True, timeout=30)
                assert proc.returncode == (0 if success else 1), "PSBT probe status " + name + ": " + proc.stderr.decode()
                if success: same(R.parse_json(proc.stdout), expected, "probe result " + name)
                else: assert proc.stdout == b"" and b"private-sentinel" not in proc.stderr, "PSBT probe failure secrecy"
                same(observed(log), wanted, "probe request order/stopping " + name)
    print("PSBT synthetic probes/expansion: " + (only or "8/8"), flush=True)


def limits(only=None):
    parent = APP / ".lake/validation/psbt-limits"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        fixture = Path(directory) / "synthetic.json"
        count = 0
        for funded in [True, False]:
            row = next(r for r in matrix() if r["name"] == ("funded-unit" if funded else "create-descriptor-1sat"))
            args, requests, _ = plan(row)
            for stage in (["expansion", "probe", "final"] if funded else ["expansion", "final"]):
                for kind in ["size", "timeout"]:
                    selection = ("funded" if funded else "create")+"-"+stage+"-"+kind
                    if only and only != selection: continue
                    data = data_for(row)
                    index = dict(expansion=2, probe=8, final=len(requests)-1)[stage]
                    e = data["entries"][index]; value = R.result(e)
                    if kind == "size":
                        # A legal JSON envelope extension pads string and object results alike.
                        e["responses"] = [dict(status=200, json=dict(result=value, error=None, padding="x"*20000))]
                    else:
                        e["responses"][0]["test_delay_ms"] = 350
                    fixture.write_text(G.json_text(data))
                    for short in [True, False]:
                        with C.responder(fixture, response_delays=kind == "timeout") as (base, log, _):
                            payload = dict(url=base+"/wallet/single", inputs=[args[args.index("--inputs")+1]], outputs=args[args.index("--outputs")+1], funded=funded, fee="1sat",
                                   bytes=8192 if kind == "size" and short else 65536,
                                   timeout=200 if kind == "timeout" and short else 2000)
                            value = R.parse_json(C.run(["--psbt-fetch"], G.json_text(payload).encode()))
                            label = "PSBT inherited " + selection
                            if short and stage != "probe": assert value.get("error", "").startswith("rpcTransport:"), label
                            else: assert "psbt" in value, label+": "+G.json_text(value)
                            calls = observed(log)
                            wanted = requests if not short or stage == "final" else requests[:index+1]
                            if short and stage == "probe": wanted = requests[:9] + requests[11:]
                            same(calls, wanted, label+" ordered requests/stopping")
                            count += 1
        if only is None: assert count == 20, "PSBT stage limit inventory"
    print(f"PSBT supplied client: {count} stage-specific short/long controls; create expansion/final, funded expansion/probe/final; size and deadline; probe skip preserved", flush=True)


def boundaries(only=None):
    count = 0
    parent = APP / ".lake/validation/psbt-boundaries"; parent.mkdir(parents=True, exist_ok=True)
    for funded in [False, True]:
        if only in ["auth-create-none", "auth-funded-none"] and funded != (only == "auth-funded-none"): continue
        row = next(r for r in matrix() if r["name"] == ("funded-unit" if funded else "create-descriptor-1sat"))
        args, requests, expected = plan(row)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory)
            (root/".cookie").write_bytes((HERE/"recordings/bitcoin-dir/.cookie").read_bytes())
            (root/".bitcoin").mkdir()
            (root/".bitcoin/.cookie").write_bytes((HERE/"recordings/bitcoin-dir/.cookie").read_bytes())
            for mode in ["cookie", "none", "user-only", "password-only", "wrong"]:
                if only and only != "auth" and only != ("auth-funded-none" if funded else "auth-create-none"): continue
                if only in ["auth-create-none", "auth-funded-none"] and mode != "none": continue
                with C.responder(HERE/("recordings/"+row["case"]+".json")) as (base, log, _):
                    auth = {"cookie": ["--bitcoin-dir", str(root)], "none": [],
                            "user-only": ["--rpc-user", "private-user"],
                            "password-only": ["--rpc-password", "private-password"],
                            "wrong": ["--rpc-user", "private-user", "--rpc-password", "private-password"]}[mode]
                    proc = network.checked_run(EXE, args+["--rpc-url", base+"/wallet/single", *auth], stub_url=base,
                                               cwd=root, env=dict(os.environ, HOME=str(root), LCK_TEST_COOKIE_HOME=str(root)), capture_output=True, timeout=20)
                    if mode == "cookie":
                        assert proc.returncode == 0 and proc.stderr == b"", "PSBT cookie handler success"
                        same(R.parse_json(proc.stdout), expected, "cookie full result")
                        same(observed(log), requests, "cookie ordered authenticated requests")
                    else:
                        assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr == b"rpcHttp: HTTP 401\n", "PSBT handler auth failure secret suppression"
                        same(observed(log), [requests[0], requests[2]], "auth ignored initial info then required expansion failure")
                    count += 1
            if only is None or only == "colon":
                # Last-colon parsing succeeds; the Core-facing split rejects only after expansion.
                args[args.index("--outputs")+1] = "x:y:1000sat"
                with C.responder(HERE/("recordings/"+row["case"]+".json")) as (base, log, _):
                    proc = network.checked_run(EXE, args+["--rpc-url", base+"/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"], stub_url=base, cwd=root, capture_output=True, timeout=20)
                    assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.startswith(b"invalidOutputs:"), "PSBT colon boundary refusal"
                    same(observed(log), requests[:8], "colon expansion before refusal/no final submission")
                    count += 1
            if funded and (only is None or only == "nonmultipath"):
                data = data_for(row); descriptor = requests[2][1][0]
                entries = copy.deepcopy(data["entries"][2:5])
                # Independent synthetic transport: repeat the public receiving descriptor info
                # for initial import; return an explicit error for the unrecorded final request.
                initial = copy.deepcopy(entries[0]); initial["responses"] *= 2
                finalparams = [[dict(txid=u["txid"], vout=u["vout"]) for u in R.result(entries[-1])], requests[-1][1][1], 0]
                fixture = root/"synthetic.json"
                controls = [initial, copy.deepcopy(data["entries"][1]), *entries[1:]]
                final = entry("walletcreatefundedpsbt", finalparams, error=dict(code=-99, message="synthetic no-change transport")); final["path"] = "/wallet/single"
                controls.append(final); fixture.write_text(G.json_text(dict(entries=controls)))
                with C.responder(fixture) as (base, log, _):
                    proc = network.checked_run(EXE, [args[0], "--network", "regtest", "--inputs", descriptor, "--outputs", next(iter(requests[-1][1][1]))+":1000000sat", "--rpc-url", base+"/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"], stub_url=base, cwd=root, capture_output=True, timeout=20)
                    assert proc.returncode == 1 and proc.stderr == b"rpcError: Core rejected the request\n", "PSBT nonmultipath final synthetic refusal"
                    wanted = [[initial["rpc"]["method"], initial["rpc"]["params"][0]], requests[1], *requests[2:5], ["walletcreatefundedpsbt", finalparams]]
                    same(observed(log), wanted, "nonmultipath descriptor no change probe/empty options omitted")
                    count += 1
    if only is None: assert count == 13, "PSBT auth/colon/no-change inventory"
    print(f"PSBT handler boundaries: {count} auth/colon/nonmultipath controls; owned explicit and conventional HOME cookies; synthetic final no-change refusal", flush=True)


def fifo():
    parent = APP / ".lake/validation/psbt-fifo"; parent.mkdir(parents=True, exist_ok=True)
    for command in ["create-both", "funded-both"]:
        row = next(r for r in matrix() if r["name"] == command)
        args, _, expected = plan(row)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory); os.mkfifo(root / "output.json"); os.mkfifo(root / "raw.psbt")
            with C.responder(HERE / ("recordings/" + row["case"] + ".json")) as (base, log, _):
                program = "import pathlib,sys; r=pathlib.Path(sys.argv[1]); a=(r/'output.json').open('rb'); b=(r/'raw.psbt').read_bytes(); (r/'raw.read').write_bytes(b); (r/'json.read').write_bytes(a.read())"
                reader = subprocess.Popen([sys.executable, "-B", "-c", program, str(root)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                writer = None
                try:
                    args += ["--rpc-url", base+"/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"]
                    network.refuse_spawn(args, base)
                    writer = subprocess.Popen([str(EXE), *args], cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = reader.communicate(timeout=15)
                    assert reader.returncode == 0 and stdout == stderr == b"", "PSBT ordered FIFO consumer"
                    same(R.parse_json((root / "json.read").read_bytes()), expected, "FIFO full JSON at EOF")
                    assert (root / "raw.read").read_bytes() == expected["psbt"].encode(), "PSBT FIFO raw exact bytes"
                    stdout, stderr = writer.communicate(timeout=15)
                    assert writer.returncode == 0 and stdout == stderr == b"", "PSBT FIFO writer completes"
                finally:
                    for child in [reader, writer]:
                        if child is not None:
                            if child.poll() is None: child.kill()
                            child.communicate(timeout=5)
    print("PSBT controlled FIFOs: 2/2 retained JSON writers, raw-before-JSON, no reopen; all children reaped", flush=True)


def scanner(only=None):
    """Large argv entries and repeated grouped commas must fail promptly before RPC."""
    parent = APP / ".lake/validation/psbt-scanner"; parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        with C.responder(HERE / "recordings/multipath-create.json") as (base, log, _):
            for kind in ["create", "funded"]:
                command = "onchain-create-funded-psbt" if kind == "funded" else "onchain-create-psbt"
                for name, outputs, error in [
                    ("long-entry", "a" * 100000, b"invalidOutputs:"),
                    ("many-commas", "destination:" + "," * 20000 + "1btc", b"invalidNumber:")]:
                    selected = kind + "-" + name
                    if only and only != selected: continue
                    args = [command, "--inputs", "synthetic:0", "--outputs", outputs, "--rpc-url", base]
                    start = time.monotonic()
                    proc = network.checked_run(EXE, args, stub_url=base, cwd=directory,
                                               capture_output=True, timeout=60)
                    elapsed = time.monotonic() - start
                    assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.startswith(error), "PSBT scanner exact refusal " + selected
                    assert observed(log) == [], "PSBT scanner zero RPC " + selected
                    print(f"PSBT scanner {selected}: {elapsed:.3f}s", flush=True)
                    assert elapsed < 3, "PSBT scanner bounded work " + selected
                    count += 1
    assert count == (1 if only else 4), "PSBT scanner long inventory"
    print(f"PSBT scanner argv bounds: {count} exact refusals; zero RPC; long entries and repeated commas", flush=True)


def replay():
    captures = json.loads(DEST.read_bytes())
    assert captures["revision"] == PIN and len(captures["captures"]) == 17, "PSBT reference capture inventory"
    for row, reference in zip(matrix(), captures["captures"]):
        actual = one(row)
        assert actual["name"] == reference["name"], "PSBT capture identity"
        if row.get("rate") == "0.00000001":
            assert reference["status"] == 0 and reference["stderr"] == "", "PSBT actual reference bare fee exception"
        else:
            assert actual["status"] == reference["status"] == 0 and actual["stderr"] == reference["stderr"] == "", "PSBT pinned status/independent stderr"
            for field in ["stdout"]:
                if actual[field]: assert not differences(exact_json(actual[field]), exact_json(reference[field])), "PSBT pinned full JSON"
            assert actual["files"]["raw.psbt"] == reference["files"]["raw.psbt"], "PSBT pinned exact raw bytes"
            if actual["files"]["output.json"]:
                assert not differences(exact_json(actual["files"]["output.json"]), exact_json(reference["files"]["output.json"])), "PSBT pinned JSON file values"
        print("PSBT replay: " + row["name"], flush=True)
    print("PSBT handler captures: 17/17; three bare-fee exceptions; original 616 offline + 18 list captures retained", flush=True)


def main():
    args = sys.argv[1:]
    if args[:1] == ["--capture-exact-one"]:
        assert network.isolated() and not network.sandbox(), "PSBT exact capture namespace"
        row = next(r for r in exact_cases() if r[0] == args[1])
        Path(args[3]).write_text(json.dumps(exact_one(row, Path(args[2])), indent=2)+"\n")
        return 0
    if args == ["--capture-exact"]:
        assert not (network.isolated() or network.sandbox()), "PSBT exact capture parent"
        build = network.run_owned(BUILD, capture_output=True, timeout=1800)
        logs = APP/".lake/validation/85g/round2"
        for stream in ["stdout", "stderr"]: (logs/("reference-build."+stream)).write_bytes(getattr(build, stream))
        (logs/"reference-build.status").write_text(str(build.returncode)+"\n")
        assert build.returncode == 0, "PSBT pinned exact build"
        reference = Path(build.stdout.decode().strip())/"bin/cyberkrill"
        records = []
        with tempfile.TemporaryDirectory(dir=logs) as directory:
            for row in exact_cases():
                record = Path(directory)/(row[0]+".json")
                status = network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), "--capture-exact-one", row[0], str(reference), str(record)], timeout=60)
                assert status == 0 and record.exists(), "PSBT exact reference execution " + row[0]
                records.append(json.loads(record.read_bytes()))
        captures = json.loads(DEST.read_bytes())
        captures["exact_amount_exceptions"] = records
        DEST.write_text(json.dumps(captures, indent=2)+"\n")
        print("PSBT exact reference captures: 2 recorded-handler + 4 synthetic transport/probe controls; original 17/11 observations retained")
        return 0
    if args[:1] == ["--capture-numeric-one"]:
        assert network.isolated() and not network.sandbox(), "PSBT numeric capture namespace"
        row = next(r for r in numeric_cases() if r[0] == args[1])
        Path(args[3]).write_text(json.dumps(numeric_one(row, Path(args[2])), indent=2)+"\n")
        return 0
    if args[:1] == ["--capture-one"]:
        assert network.isolated() and not network.sandbox(), "PSBT capture needs fresh namespace"
        row = next(r for r in matrix() if r["name"] == args[1])
        Path(args[3]).write_text(json.dumps(one(row, Path(args[2])), indent=2) + "\n")
        return 0
    if args == ["--capture"]:
        assert not (network.isolated() or network.sandbox()), "PSBT capture parent"
        build = network.run_owned(BUILD, capture_output=True, timeout=1800)
        logs = APP / ".lake/validation/85g"
        for stream in ["stdout", "stderr"]: (logs / ("reference-build." + stream)).write_bytes(getattr(build, stream))
        (logs / "reference-build.status").write_text(str(build.returncode) + "\n")
        assert build.returncode == 0, "PSBT pinned build"
        reference = Path(build.stdout.decode().strip()) / "bin/cyberkrill"
        records = []; controls = []
        with tempfile.TemporaryDirectory(dir=logs) as directory:
            for row in matrix():
                record = Path(directory) / (row["name"] + ".json")
                status = network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), "--capture-one", row["name"], str(reference), str(record)], timeout=60)
                assert status == 0 and record.exists(), "PSBT actual reference execution " + row["name"]
                records.append(json.loads(record.read_bytes()))
            for row in numeric_cases():
                record = Path(directory)/("numeric-"+row[0]+".json")
                status = network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), "--capture-numeric-one", row[0], str(reference), str(record)], timeout=60)
                assert status == 0 and record.exists(), "PSBT numeric reference capture " + row[0]
                controls.append(json.loads(record.read_bytes()))
        DEST.write_text(json.dumps(dict(upstream="https://github.com/douglaz/cyberkrill", revision=PIN, captures=records, synthetic_numeric_controls=controls), indent=2) + "\n")
        print("PSBT reference captures: 17/17 recorded-reply handlers; 11/11 separate synthetic numeric controls")
        return 0
    if not (network.isolated() or network.sandbox()):
        return network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), *args], timeout=240)
    if args[:1] == ["replay"]:
        if len(args) > 1: one(next(r for r in matrix() if r["name"] == args[1]))
        else: replay()
        return 0
    if args[:1] == ["synthetic"]: synthetic(args[1] if len(args) > 1 else None); return 0
    if args == ["refusals"]: refusals(); return 0
    if args == ["injected"]: print(C.run(["--psbt-injected"]), end=""); return 0
    if args[:1] == ["whitespace"]:
        assert len(args) == 2, "PSBT whitespace selector"
        os.environ["LCK_TEST_PSBT_WHITESPACE"] = args[1]
        print(C.run(["--psbt-injected"]), end="")
        return 0
    if args[:1] == ["deep"]: deep_validation(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["spelling"]: spelling(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["probes"]: probes(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["limits"]: limits(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["boundaries"]: boundaries(args[1] if len(args) > 1 else None); return 0
    if args == ["fifo"]: fifo(); return 0
    if args[:1] == ["scanner"]: scanner(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["numeric"]: numeric(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["exact"]: exact(args[1] if len(args) > 1 else None); return 0
    assert args == [], "PSBT test selector"
    replay(); synthetic(); refusals(); deep_validation(); spelling(); probes(); limits(); boundaries(); fifo(); numeric(); exact(); scanner()
    print(C.run(["--psbt-injected"]), end="")
    return 0


if __name__ == "__main__": sys.exit(main())
