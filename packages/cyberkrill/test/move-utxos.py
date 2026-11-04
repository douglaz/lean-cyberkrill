#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Move handler recordings, exact reference comparisons and synthetic controls."""
import copy
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from cases import APP, ROOT, PIN, BUILD
import network
C = importlib.import_module("rpc-client")
G, R = C.G, C.R
P = importlib.import_module("psbt-commands")
HERE = APP / "test"
EXE = APP / ".lake/build/bin/cyberkrill"
TEST = APP / ".lake/build/bin/CyberkrillTests"
DEST = HERE / "golden/move-utxos-reference.json"
PROVENANCE = HERE / "move-utxos-provenance.json"


def matrix():
    rows = [
        dict(name="absolute", case="move-success", fee="1000sat"),
        dict(name="absolute-bare", case="move-success", fee="0.00001", exception="feeUnitRequired"),
        dict(name="rate", case="move-success", rate="9.091sats"),
        dict(name="rate-bare", case="move-success", rate="0.00000009091", exception="feeUnitRequired"),
        dict(name="cap-exact", case="move-success", fee="1000sat", cap="0.4"),
        dict(name="cap-above", case="move-success", fee="1000sat", cap="0.5"),
        dict(name="standalone-descriptor", case="move-success", fee="1000sat", ignored=True),
        dict(name="cookie", case="move-success", fee="1000sat", cookie=True),
        dict(name="relative-cookie", case="move-success", fee="1000sat", cookie="relative"),
        dict(name="json", case="move-success", fee="1000sat", files="json"),
        dict(name="raw", case="move-success", fee="1000sat", files="raw"),
        dict(name="both", case="move-success", fee="1000sat", files="both"),
        dict(name="alias", case="move-success", fee="1000sat", files="alias"),
        dict(name="descriptor-exact-cap", case="move-unclamped", fee="1660sat", cap="60000000sat", descriptor=True),
        dict(name="overshoot", case="move-unclamped", fee="1660sat", cap="50000000sat", descriptor=True, exception="fullSelectedTotal"),
        dict(name="f64", case="move-f64", fee="1660sat", exception="exactAmount"),
    ]
    assert len(rows) == 16, "move capture inventory"
    return rows


def same(actual, expected, label):
    assert G.selector(actual) == G.selector(expected), "move " + label


def data_for(case):
    return R.parse_json((HERE / "recordings" / (case + ".json")).read_bytes())


def observed(log):
    return [[R.parse_json(r["body"])["method"], R.parse_json(r["body"])["params"]] for r in C.logged(log)]


def plan(row, reference=False):
    data = data_for(row["case"])
    final = [e for e in data["entries"] if e["rpc"]["method"] == "createpsbt"]
    final = final[0] if reference and row.get("exception") in {"fullSelectedTotal", "exactAmount"} else final[-1]
    params = final["rpc"]["params"][0]
    args = ["onchain-move-utxos", "--network", "ReGtEsT"]
    if row.get("descriptor"):
        inputs = [data["entries"][0]["rpc"]["params"][0][0]]
        requests = [[e["rpc"]["method"], e["rpc"]["params"][0]] for e in data["entries"] if e["rpc"]["method"] != "createpsbt"]
    else:
        inputs = [str(p["txid"]) + ":+" + str(int(p["vout"])) for p in data["capture"]["funding"][:3 if row["case"] == "move-f64" else 1]]
        requests = [[e["rpc"]["method"], e["rpc"]["params"][0]] for e in data["entries"] if e["rpc"]["method"] == "getrawtransaction"]
    for i, value in enumerate(inputs):
        args += ["--inputs=" + value] if i % 2 else ["--inputs", " " + value + " "]
    args += ["--destination", next(iter(params[1]))]
    args += ["--fee-rate", row["rate"]] if "rate" in row else ["--fee", row["fee"]]
    if row.get("cap"): args += ["--max-amount=" + row["cap"]]
    if row.get("ignored"): args += ["--descriptor", "ignored"]
    files = row.get("files")
    if files in {"json", "both"}: args += ["-ooutput.json"]
    if files in {"raw", "both"}: args += ["--psbt-output=raw.psbt"]
    if files == "alias": args += ["--output=shared.json", "--psbt-output=shared.json"]
    expected = dict(psbt=R.result(final), fee_sats=1660 if row["case"] != "move-success" else 1000, change_position=None)
    requests.append(["createpsbt", params])
    return args, requests, expected


def one(row, reference=None):
    args, requests, expected = plan(row, reference is not None)
    with tempfile.TemporaryDirectory(prefix="move-replay-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        with C.responder(HERE / "recordings" / (row["case"] + ".json")) as (base, log, _):
            args += ["--rpc-url", base + "/wallet/single"]
            if row.get("cookie"):
                if row["cookie"] == "relative":
                    shutil.copyfile(HERE / "recordings/bitcoin-dir/.cookie", root / ".cookie")
                    args += ["--bitcoin-dir="]
                else:
                    shutil.copytree(HERE / "recordings/bitcoin-dir", root / "bitcoin-dir")
                    args += ["--bitcoin-dir", "bitcoin-dir"]
            else:
                args += ["--rpc-user", "lck", "--rpc-password", "lck-throwaway"]
            if reference:
                result = G.run([str(reference), *args], stub_url=base, reference=True,
                               cwd=root, env=dict(os.environ, HOME=str(root)), timeout=30, check=False)
            else:
                result = network.checked_run(EXE, args, stub_url=base, cwd=root,
                    env=dict(os.environ, HOME=str(root)), stdin=subprocess.DEVNULL,
                    capture_output=True, timeout=30)
            actual = observed(log)
            bare = row.get("exception") == "feeUnitRequired" and not reference
            failed = row.get("exception") == "exactAmount" and reference
            if bare:
                assert result.returncode == 1 and result.stdout == b"" and result.stderr == b"feeUnitRequired: Specify a Bitcoin unit, for example 15sats\n", "move bare fee handler refusal"
                same(actual, [], "bare fee zero RPC")
            elif failed:
                assert result.returncode == 1 and result.stdout == b"" and b"Invalid amount" in result.stderr, "move reference f64 Core refusal"
                same(actual, requests, "reference f64 ordered requests")
            else:
                assert result.returncode == 0 and result.stderr == b"", "move CLI success " + row["name"] + ": " + result.stderr.decode()
                filename = "shared.json" if row.get("files") == "alias" else "output.json"
                output = (root / filename).read_bytes() if row.get("files") in {"json", "both", "alias"} else result.stdout
                assert output and not output.endswith(b"\n"), "move JSON no newline"
                same(R.parse_json(output), expected, "complete JSON " + row["name"])
                assert (result.stdout == b"") == (row.get("files") in {"json", "both", "alias"}), "move stdout/file contract"
                if row.get("files") in {"raw", "both"}:
                    assert (root / "raw.psbt").read_bytes() == expected["psbt"].encode(), "move raw bytes no newline"
                same(actual, requests, "ordered exact requests " + row["name"])
            assert all(r["path"] == "/wallet/single" for r in C.logged(log)), "move case-local wallet endpoint"
            return dict(name=row["name"], status=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode(),
                files={p: (root / p).read_text() if (root / p).exists() else None for p in ["output.json", "raw.psbt", "shared.json"]},
                requests=G.json_text(actual))


def replay(only=None):
    captures = json.loads(DEST.read_bytes())
    assert captures["revision"] == PIN and len(captures["captures"]) == 16, "move pinned reference"
    exceptions = {"absolute-bare": "feeUnitRequired", "rate-bare": "feeUnitRequired",
                  "overshoot": "fullSelectedTotal", "f64": "exactAmount"}
    assert captures["exceptions"] == exceptions, "move precise exception inventory"
    for row, reference in zip(matrix(), captures["captures"]):
        assert row["name"] == reference["name"], "move reference identity"
        if only and only != row["name"]: continue
        port = one(row)
        if row["name"] in exceptions:
            if row["name"].endswith("-bare"):
                assert reference["status"] == 0 and reference["stderr"] == "" and port["status"] == 1
                same(R.parse_json(reference["stdout"]), plan(row, True)[2], "reference bare complete success")
            elif row["name"] == "f64":
                assert reference["status"] == 1 and "Invalid amount" in reference["stderr"] and port["status"] == 0
            else:
                assert reference["status"] == port["status"] == 0
                same(R.parse_json(reference["stdout"]), plan(row, True)[2], "reference clamped complete result")
                assert reference["stdout"] != port["stdout"], "move no-clamp observed delta"
        else:
            assert port["status"] == reference["status"] == 0 and port["stderr"] == reference["stderr"] == ""
            for field in ["stdout"]:
                if port[field]: same(R.parse_json(port[field]), R.parse_json(reference[field]), "pinned complete stdout")
            for filename in port["files"]:
                a, b = port["files"][filename], reference["files"][filename]
                if filename.endswith(".json") and a: same(R.parse_json(a), R.parse_json(b), "pinned file JSON")
                else: assert a == b, "move pinned raw file bytes"
        print("move replay: " + row["name"], flush=True)
    if only is None: print("move captures: 16/16; 4 precise exceptions; both actual bare fee handler goldens", flush=True)


def entry(method, params, result=None, error=None):
    return dict(method="POST", path="/synthetic", rpc=dict(method=method, params=[params]),
                responses=[dict(status=200, json=dict(result=result, error=error))])


def control(name, values, *, cap=None, fee="1sat", rate=None, bad=None,
            expect_error=None, expected_order=None, requested=None, repeats=None):
    """Synthetic transport, with a recorded PSBT as the validation payload only."""
    psbt = R.result(data_for("move-success")["entries"][-1])
    if bad is not None: psbt = bad(psbt)
    inputs = [dict(txid="synthetic-" + str(i), vout=0) for i in range(len(values))]
    if repeats: inputs = [inputs[0]] * len(values)
    selected = list(range(len(values)))
    if cap is not None:
        selected = []
        total = Decimal(0)
        for i in sorted(range(len(values)), key=lambda i: values[i], reverse=True):
            if total >= Decimal(int(Decimal(cap) * 100000000)) / 100000000: break
            selected.append(i); total += values[i]
    total = sum((values[i] for i in selected), Decimal(0))
    # Independent P2WPKH weight arithmetic for one 22-byte output.
    count = len(selected)
    weight = 164 + count * 272 + (2 if count else 0)
    sats = int(Decimal(str(rate)) * ((weight + 3)//4) + Decimal("0.5")) if rate is not None else int(Decimal(fee.removesuffix("sat")))
    amount = total - Decimal(sats) / 100000000
    entries = []
    for i, inp in enumerate(inputs):
        value = requested[i] if requested else dict(vout=[dict(value=values[i], n=91)])
        found = next((e for e in entries if e["rpc"]["params"] == [[inp["txid"], True]]), None)
        if found:
            found["responses"].append(dict(status=200, json=dict(result=value, error=None)))
        else: entries.append(entry("getrawtransaction", [inp["txid"], True], value))
    finalparams = [[inputs[i] for i in selected], {"destination": amount}, 0, False]
    if amount > 0 and selected and not (expect_error and expect_error.startswith(("rpcInvalid", "rpcError"))):
        entries.append(entry("createpsbt", finalparams, psbt))
    with tempfile.TemporaryDirectory(prefix="move-controls-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        fixture = root / "synthetic.json"; fixture.write_text(G.json_text(dict(entries=entries)))
        (root / "raw").write_text("unchanged")
        (root / "json").write_text("truncate")
        with C.responder(fixture) as (base, log, _):
            args = ["onchain-move-utxos", "--destination", "destination", "--rpc-url", base + "/synthetic"]
            for inp in inputs: args += ["--inputs", inp["txid"] + ":" + str(inp["vout"])]
            args += ["--fee-rate", str(rate)+"sats"] if rate is not None else ["--fee", fee]
            if cap is not None: args += ["--max-amount", str(cap)+"btc"]
            args += ["--psbt-output", "raw", "--output", "json"]
            proc = network.checked_run(EXE, args, stub_url=base, cwd=root,
                env=dict(os.environ, HOME=str(root)), capture_output=True, timeout=20)
            actual = observed(log)
            if expect_error:
                assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.startswith(expect_error.encode()), "move synthetic refusal " + name
                assert (root/"raw").read_bytes() == b"unchanged" and (root/"json").read_bytes() == b"", "move validation raw untouched/JSON truncated " + name
                if expect_error.startswith(("insufficientFunds", "emptySelection")):
                    same(actual, [["getrawtransaction", [i["txid"], True]] for i in inputs], "all lookups before refusal " + name)
            else:
                assert proc.returncode == 0 and proc.stdout == proc.stderr == b"", "move synthetic success " + name
                same(R.parse_json((root/"json").read_bytes()), dict(psbt=psbt,fee_sats=sats,change_position=None), "synthetic result " + name)
                same(actual, [["getrawtransaction", [i["txid"], True]] for i in inputs]+[["createpsbt", finalparams]], "synthetic ordered requests " + name)
                assert (root/"raw").read_bytes() == psbt.encode(), "move original raw " + name
                if expected_order is not None:
                    assert selected == expected_order, "move independently selected order " + name
            return proc


def controls(only=None):
    values = [Decimal("0.1"), Decimal("0.4"), Decimal("0.2"), Decimal("0.4")]
    rows = [
        ("no-cap", dict(values=values, expected_order=[0,1,2,3])),
        ("below-largest", dict(values=values, cap="0.01", expected_order=[1])),
        ("exact-cap", dict(values=values, cap="0.4", expected_order=[1])),
        ("overshoot", dict(values=values, cap="0.5", expected_order=[1,3])),
        ("above-total", dict(values=values, cap="2", expected_order=[1,3,2,0])),
        ("zero-cap", dict(values=values, cap="0", expect_error="emptySelection:")),
        ("fractional-cap", dict(values=values, cap="0.40000000999", expected_order=[1])),
        ("equal-fee", dict(values=[Decimal("0.00000001")], fee="1sat", expect_error="insufficientFunds:")),
        ("greater-fee", dict(values=[Decimal("0.00000001")], fee="2sat", expect_error="insufficientFunds:")),
        ("zero-fee", dict(values=values, fee="0sat")),
        ("fractional-fee", dict(values=values, fee="1.999sat")),
        ("subsat-fee", dict(values=values, fee="0.999sat")),
        ("fractional-rate", dict(values=values, rate="2.5")),
        ("capped-rate", dict(values=values, cap="0.1", rate="2.5", expected_order=[1])),
        ("zero-rate", dict(values=values, rate="0")),
        ("exact-values", dict(values=[Decimal("9007199254740993.00000000001")])),
        ("rounding-rate", dict(values=[Decimal("0.1")], rate="0.005")),
        ("duplicate-input", dict(values=[Decimal("0.1")]*2, repeats=True)),
        ("unrelated-fields", dict(values=[Decimal("0.1")], requested=[dict(txid=False,vout=[dict(n=17,value=Decimal("0.1")),dict(value="bad")])])),
        ("missing-output", dict(values=[Decimal("0.1")], requested=[dict(vout=[])], expect_error="rpcInvalidResult:")),
        ("missing-value", dict(values=[Decimal("0.1")], requested=[dict(vout=[{}])], expect_error="rpcInvalidResult:")),
        ("invalid-unselected", dict(values=[Decimal("0.4"), Decimal("0.1")],cap="0.1",requested=[dict(vout=[dict(value=Decimal("0.4"))]),dict(vout=[dict(value=-1)])],expect_error="rpcInvalidAmount:")),
    ]
    for suffix in [" ", "\n", "\t", "\r\n", "\u00a0"]:
        rows.append(("psbt-space-"+str(ord(suffix[0])),dict(values=[Decimal("0.1")],bad=lambda p,s=suffix:p+s,expect_error="psbtBase64:")))
    rows += [
        ("psbt-padding", dict(values=[Decimal("0.1")],bad=lambda p:p+"=",expect_error="psbtBase64:")),
        ("psbt-structure", dict(values=[Decimal("0.1")],bad=lambda p:"cHNidP8=",expect_error="psbt")),
    ]
    assert len(rows) == 29, "move synthetic inventory"
    for name, kwargs in rows:
        if only and name != only: continue
        control(name, **kwargs)
    print("move synthetic controls: "+str(1 if only else len(rows))+"; payloads are recorded PSBTs or test-only mutations, not captured Core behavior",flush=True)


def refusals():
    row = matrix()[0]; args, _, _ = plan(row)
    count = 0
    with tempfile.TemporaryDirectory(prefix="move-refusals-",dir=os.environ["TMPDIR"]) as directory:
        root=Path(directory)
        with C.responder(HERE/"recordings/move-success.json") as (base,log,_):
            for extra, error, status in [
                (["--fee-rate","1sat"],"invalidArguments:",1),
                (["--fee","2sat"],"invalidArguments:",1),
                (["--wallet-file","unread"],"unsupportedWalletFile:",1),
                (["--wallet-file","unread","--bitcoin-dir","unused"],"unsupportedWalletFile:",1),
                (["--descriptor","ignored","--bitcoin-dir","unused"],"unsupportedBackend:",1),
                (["--descriptor","x","--wallet-file","unread"],"invalidArguments:",1),
                (["--electrum","unused"],"invalidArguments:",1),
                (["--esplora","unused"],"invalidArguments:",1),
                (["--network","bad"],"invalidArguments:",1),
                (["--max-amount","0.1sat"],"lessThanOneSat:",1),
                (["--max-amount","broken","--help"],"invalidNumber:",1),
                (["--help","--max-amount","broken"],None,0),
                (["--max-amount","1sat","--help"],None,0),
                (["--fee=bare","--help"],"feeUnitRequired:",1),
                (["--help","--fee=bare"],None,0),
                (["--max-amount","-h"],"invalidNumber:",1),
                (["--psbt-output","--help"],"invalidArguments:",1),
            ]:
                actual=args+extra+["--rpc-url",base+"/wallet/single"]
                proc=network.checked_run(EXE,actual,stub_url=base,cwd=root,capture_output=True,timeout=15)
                assert proc.returncode==status and (proc.stderr.startswith(error.encode()) if error else not proc.stderr), "move executable refusal/help "+repr(extra)
                count+=1
            for actual in [["onchain-move-utxos"],["onchain-move-utxos","--inputs","a:0"],["onchain-move-utxos","--destination","d"]]:
                actual += ["--rpc-url",base+"/wallet/single"]
                proc=network.checked_run(EXE,actual,stub_url=base,cwd=root,capture_output=True,timeout=15)
                assert proc.returncode==1 and proc.stderr.startswith(b"invalidArguments:"),"move required flags"
                count+=1
            same(observed(log),[],"refusals zero RPC")
    print(f"move grammar/help/refusals: {count}/20; zero RPC",flush=True)


def fifo():
    row=next(r for r in matrix() if r["name"]=="both")
    args,requests,expected=plan(row)
    with tempfile.TemporaryDirectory(prefix="move-fifo-",dir=os.environ["TMPDIR"]) as directory:
        root=Path(directory); os.mkfifo(root/"output.json"); os.mkfifo(root/"raw.psbt")
        with C.responder(HERE/"recordings/move-success.json") as (base,log,_):
            program="import pathlib,sys; r=pathlib.Path(sys.argv[1]); a=(r/'output.json').open('rb'); (r/'raw.read').write_bytes((r/'raw.psbt').read_bytes()); (r/'json.read').write_bytes(a.read())"
            reader=subprocess.Popen([sys.executable,"-B","-c",program,str(root)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            writer=None
            try:
                args += ["--rpc-url",base+"/wallet/single","--rpc-user","lck","--rpc-password","lck-throwaway"]
                network.refuse_spawn(args,base)
                writer=subprocess.Popen([str(EXE),*args],cwd=root,env=dict(os.environ,HOME=str(root)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                a,b=reader.communicate(timeout=15)
                assert reader.returncode==0 and a==b==b"","move FIFO reader"
                a,b=writer.communicate(timeout=15)
                assert writer.returncode==0 and a==b==b"","move FIFO writer"
                same(R.parse_json((root/"json.read").read_bytes()),expected,"FIFO JSON")
                assert (root/"raw.read").read_bytes()==expected["psbt"].encode(),"move FIFO raw"
                same(observed(log),requests,"FIFO requests")
            finally:
                for child in [reader,writer]:
                    if child is not None:
                        if child.poll() is None:child.kill()
                        child.communicate(timeout=5)
    print("move FIFOs: retained JSON writer; raw before JSON; reaped",flush=True)


def deep(only=None):
    import base64
    source=P.data_for(P.matrix()[0])["entries"][-1]
    raw=base64.b64decode(R.result(source));boundary=P.maps(raw)[1][1]
    funded=P.data_for(next(r for r in P.matrix() if r["name"]=="funded-unit"))["entries"][-1]
    key,value,_=next(r for r in P.maps(base64.b64decode(R.result(funded)["psbt"]))[1][0] if r[0][0]==6)
    compressed=key[1:];x=int.from_bytes(compressed[1:],"big");prime=2**256-2**32-977
    y=pow((x**3+7)%prime,(prime+1)//4,prime)
    if y%2!=compressed[0]%2:y=prime-y
    uncompressed=b"\x04"+compressed[1:]+y.to_bytes(32,"big")
    for name,added,error in [
        ("curve",P.field(b"\x06\x02"+b"\xff"*32,value),"psbtInvalidKey:"),
        ("hash",P.field(b"\x0b"+b"\x00"*32,b"synthetic"),"psbtInvalidValue:"),
        ("same-point",P.field(key,value)+P.field(b"\x06"+uncompressed,value),"psbtDuplicatePoint:")]:
        if only and name!=only:continue
        corrupt=base64.b64encode(raw[:boundary]+added+raw[boundary:]).decode()
        control(name,[Decimal("0.1")],bad=lambda _:corrupt,expect_error=error)
    print("move deep PSBT validation: "+(only or "3/3 curve/hash/same-point recorded derivatives"),flush=True)


def expansions(only=None):
    original=data_for("move-unclamped")
    descriptor=original["entries"][0]["rpc"]["params"][0][0]
    for name in ["scope-dedup","derive-fallback","empty-expansion"]:
        if only and name!=only:continue
        data=copy.deepcopy(original);entries=data["entries"][:8]
        first=R.result(entries[4])[0];chosen=dict(txid=first["txid"],vout=first["vout"])
        args=["onchain-move-utxos","--inputs",descriptor,"--destination","destination","--fee","1sat"]
        wanted=[[e["rpc"]["method"],e["rpc"]["params"][0]] for e in entries]
        def set_result(e,value):e["responses"]=[dict(status=200,json=dict(result=value,error=None))]
        if name=="scope-dedup":
            for i in [4,7]:set_result(entries[i],[first,first])
            for e in entries:e["responses"]*=2
            args+=["--inputs",descriptor,"--inputs",chosen["txid"]+":"+str(int(chosen["vout"]))]
            wanted*=2
            lookup=entry("getrawtransaction",[chosen["txid"],True],dict(vout=[dict(value=Decimal("0.4"))]*(int(chosen["vout"])+1)))
            lookup["responses"]*=3;entries.append(lookup)
            wanted += [["getrawtransaction",[chosen["txid"],True]]]*3
            final=[[chosen]*3,{"destination":Decimal("1.19999999")},0,False]
        elif name=="derive-fallback":
            entries[3]["responses"]=[dict(status=200,json=dict(result=None,error=dict(code=-99,message="synthetic")))]
            entries[4]["rpc"]["params"]=[[0,9999999,[]]]
            wanted[4][1]=[0,9999999,[]]
            for e in data["entries"][8:12]:entries.append(e);wanted.append([e["rpc"]["method"],e["rpc"]["params"][0]])
            final=[[dict(txid=p["txid"],vout=p["vout"]) for p in data["capture"]["funding"]],{"destination":Decimal("0.72999999")},0,False]
            # listunspent order is pinned separately from funding order.
            selected=[dict(txid=u["txid"],vout=u["vout"]) for i in [4,7] for u in R.result(entries[i])]
            final[0]=selected
        else:
            for i in [4,7]:set_result(entries[i],[])
            final=None
        if final:
            psbt=R.result(data_for("move-success")["entries"][-1])
            entries.append(entry("createpsbt",final,psbt));wanted.append(["createpsbt",final])
        for e in entries:e["path"]="/wallet/single"
        with tempfile.TemporaryDirectory(prefix="move-expansion-",dir=os.environ["TMPDIR"]) as directory:
            root=Path(directory);fixture=root/"synthetic.json";fixture.write_text(G.json_text(dict(entries=entries)))
            with C.responder(fixture) as (base,log,_):
                proc=network.checked_run(EXE,args+["--rpc-url",base+"/wallet/single","--rpc-user","lck","--rpc-password","lck-throwaway"],
                    stub_url=base,cwd=root,env=dict(os.environ,HOME=str(root)),capture_output=True,timeout=20)
                assert proc.returncode==(1 if final is None else 0),"move expansion status "+name+": "+proc.stderr.decode()
                if final is None:assert proc.stderr.startswith(b"emptyInputs:"),"move empty expansion"
                same(observed(log),wanted,"expansion ordered params/dedup "+name)
    print("move descriptor controls: "+(only or "3/3")+"; synthetic transport; per-invocation dedup and derive fallback",flush=True)


def limits(only=None):
    row=next(r for r in matrix() if r["name"]=="descriptor-exact-cap")
    args,wanted,expected=plan(row)
    original=data_for("move-unclamped")
    # Replay only the exact final variant, keeping the selected recorded PSBT.
    entries=copy.deepcopy(original["entries"][:12]+[original["entries"][-1]])
    count=0
    for stage,index in [("expansion",2),("lookup",8),("final",12)]:
        for kind in ["size","timeout"]:
            name=stage+"-"+kind
            if only and only!=name:continue
            data=copy.deepcopy(entries)
            for response in data[index]["responses"]:
                if kind=="size":response["text"]+=" "*30000
                else:response["test_delay_ms"]=120
            with tempfile.TemporaryDirectory(prefix="move-limits-",dir=os.environ["TMPDIR"]) as directory:
                root=Path(directory);fixture=root/"synthetic.json";fixture.write_text(G.json_text(dict(entries=data)))
                for large in [False,True]:
                    with C.responder(fixture,response_delays=True) as (base,log,_):
                        actual=args+["--rpc-url",base+"/wallet/single","--rpc-user","lck","--rpc-password","lck-throwaway"]
                        network.refuse_spawn(actual,base)
                        payload=dict(args=actual,status=0 if large else 1,bytes=100000 if large or kind!="size" else 10000,
                                     timeout=1000 if large or kind!="timeout" else 30)
                        proc=subprocess.run([str(TEST),"--move-fetch"],input=G.json_text(payload).encode(),cwd=root,
                            env=dict(os.environ,HOME=str(root)),capture_output=True,timeout=20)
                        assert proc.returncode==0,"move inherited "+name+": "+proc.stderr.decode()
                        if large:
                            same(R.parse_json(proc.stdout),expected,"longer/larger success "+name)
                            same(observed(log),wanted,"longer/larger complete requests "+name)
                        else:
                            assert proc.stdout==b"" and proc.stderr==b"rpcTransport: HTTP transport failed\n","move inherited "+name
                            same(observed(log),wanted[:index+1],"bounded stop "+name)
                    count+=1
    print(f"move client limits: {count}; custom size/deadline at expansion, lookup and final, paired successes",flush=True)


def auth(only=None):
    args,wanted,expected=plan(matrix()[0])
    count=0
    with tempfile.TemporaryDirectory(prefix="move-auth-",dir=os.environ["TMPDIR"]) as directory:
        root=Path(directory);(root/".bitcoin").mkdir()
        shutil.copyfile(HERE/"recordings/bitcoin-dir/.cookie",root/".bitcoin/.cookie")
        (root/"cookie").mkdir();(root/"cookie/.cookie").write_text("bad-cookie")
        for name,extra,success in [
            ("none",[],False),("user",["--rpc-user","lck"],False),
            ("password",["--rpc-password","lck-throwaway"],False),
            ("fallback",["--bitcoin-dir","cookie"],False),
            ("bad",["--rpc-user","private-user","--rpc-password","private-password"],False)]:
            if only and only!=name:continue
            with C.responder(HERE/"recordings/move-success.json") as (base,log,_):
                proc=network.checked_run(EXE,args+extra+["--rpc-url",base+"/wallet/single"],stub_url=base,cwd=root,
                    env=dict(os.environ,HOME=str(root)),capture_output=True,timeout=15)
                assert proc.returncode==1 and proc.stdout==b"" and proc.stderr==b"rpcHttp: HTTP 401\n","move auth secret suppression "+name
                same(observed(log),wanted[:1],"auth stops at first lookup "+name)
                count+=1
    print(f"move handler authentication: {count}; partial pairs/401/no implicit HOME cookie",flush=True)


def scope_bytes():
    import io
    from unittest.mock import patch
    scope=importlib.import_module("scope")
    target=ROOT/".beads/issues.jsonl"
    raw=target.read_bytes()
    scope.main()
    lines=raw.splitlines(keepends=True)
    index=next(i for i,line in enumerate(lines) if json.loads(line)["id"]!=scope.ISSUE)
    changed=lines[:];changed[index]=b" "+changed[index]
    altered=b"".join(changed)
    original=Path.open
    def opened(path,*args,**kwargs):
        if path==target:return io.BytesIO(altered)
        return original(path,*args,**kwargs)
    error=""
    try:
        with patch.object(Path,"open",opened):scope.main()
    except AssertionError as failure:error=str(failure)
    assert error=="unrelated raw issue bytes changed","move scope raw serialization"
    print("move scope: byte-only unrelated JSONL change detected independently of field equality",flush=True)


def capture():
    assert not (network.isolated() or network.sandbox()),"move capture parent"
    build=network.run_owned(BUILD,capture_output=True,timeout=1800)
    logs=APP/".lake/validation/move-capture"; logs.mkdir(parents=True,exist_ok=True)
    for stream in ["stdout","stderr"]:(logs/("reference-build."+stream)).write_bytes(getattr(build,stream))
    (logs/"reference-build.status").write_text(str(build.returncode)+"\n")
    assert build.returncode==0,"move pinned reference build"
    reference=Path(build.stdout.decode().strip())/"bin/cyberkrill"
    records=[]
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
        for row in matrix():
            record=Path(directory)/(row["name"]+".json")
            status=network.run_isolated([sys.executable,"-B",str(Path(__file__).resolve()),"--capture-one",row["name"],str(reference),str(record)],timeout=60)
            assert status==0 and record.exists(),"move actual reference capture "+row["name"]
            records.append(json.loads(record.read_bytes()))
    DEST.write_text(json.dumps(dict(upstream="https://github.com/douglaz/cyberkrill",revision=PIN,
        captures=records,exceptions={r["name"]:r["exception"] for r in matrix() if "exception" in r}),indent=2)+"\n")
    paths=["cyberkrill/src/main.rs","cyberkrill-core/src/bitcoin_rpc.rs"]
    PROVENANCE.write_text(json.dumps(dict(revision=PIN,
        sources=[dict(url="https://github.com/douglaz/cyberkrill",revision=PIN,path=p,licence="MIT",sha256=G.SOURCE_HASHES[p],changes="Read command and client behavior; captured CLI against recorded Core replies") for p in paths],
        captures=16,exceptions=4,fixture_sha256={str(p.relative_to(APP)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [HERE/"recordings"/(c+".json") for c in ["move-success","move-f64","move-unclamped"]]},
        capture_sha256=hashlib.sha256(DEST.read_bytes()).hexdigest()),indent=2)+"\n")
    print("move actual pinned reference captures: 16/16",flush=True)


def strict_raw(only=None):
    # Requested array element 1 has n=0; identity and unrelated output validity
    # are deliberately independent of the move command's consumption.
    cases = [
        ("missing-identity", {"vout": [{"value": Decimal("0.00000001")}, {"n": 0, "value": Decimal("0.00000002")}]}, False),
        ("malformed-identity", {"txid": False, "vout": [{"value": Decimal("0.00000001")}, {"n": 0, "value": Decimal("0.00000002")}]}, False),
        ("missing-unrelated", {"txid": "synthetic", "vout": [{}, {"n": 0, "value": Decimal("0.00000002")}]}, False),
        ("malformed-unrelated", {"txid": "synthetic", "vout": [{"value": "unusable"}, {"n": 0, "value": Decimal("0.00000002")}]}, False),
        ("valid", {"txid": "synthetic", "vout": [{"value": Decimal("0.00000001")}, {"n": 0, "value": Decimal("0.00000002")}]}, True),
    ]
    for name, raw, valid in cases:
        if only and only != name: continue
        with tempfile.TemporaryDirectory(prefix="move-strict-", dir=os.environ["TMPDIR"]) as directory:
            root = Path(directory)
            recording = root / "synthetic.json"
            recording.write_text(G.json_text(dict(entries=[entry("getrawtransaction", ["synthetic", True], raw)])))
            with C.responder(recording) as (base, log, _):
                payload = dict(url=base + "/synthetic", raw=raw, index=1, valid=valid)
                result = subprocess.run([str(TEST), "--move-raw"], input=G.json_text(payload).encode(),
                                        cwd=root, capture_output=True, timeout=15)
                sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
                assert result.returncode == 0, "move strict raw rejection " + name
                same(observed(log), [["getrawtransaction", ["synthetic", True]]], "strict raw request")
    print("move strict/narrow raw contracts: " + str(1 if only else 5) + " synthetic controls", flush=True)


def preprocessing():
    # Parse-only cases; no required inputs or destination can reach execution.
    for command in ["onchain-create-psbt", "onchain-create-funded-psbt"]:
        for unsupported in ["--fee", "--destination", "--max-amount"]:
            for suffix, error, status in [
                (["--fee-rate=bare"], b"feeUnitRequired:", 1),
                (["--help", "--fee-rate=bare"], b"invalidArguments:", 1),
                (["--fee-rate=bare", "--help"], b"feeUnitRequired:", 1),
            ]:
                result = subprocess.run([str(EXE), command, unsupported, *suffix],
                                        capture_output=True, timeout=15)
                assert result.returncode == status and (result.stderr.startswith(error) if error else not result.stderr), "move preserves existing preprocessing"
    print("existing creation preprocessing: 18 parse-only typed/help controls", flush=True)


def main():
    args=sys.argv[1:]
    if args==["--capture"]: capture(); return 0
    if args==["scope-bytes"]: scope_bytes(); return 0
    if args[:1]==["--capture-one"]:
        assert network.isolated() and not network.sandbox(),"move reference isolated"
        row=next(r for r in matrix() if r["name"]==args[1])
        Path(args[3]).write_text(json.dumps(one(row,Path(args[2])),indent=2)+"\n")
        return 0
    if not (network.isolated() or network.sandbox()):
        return network.run_isolated([sys.executable,"-B",str(Path(__file__).resolve()),*args],timeout=240)
    if args[:1]==["replay"]: replay(args[1] if len(args)>1 else None)
    elif args[:1]==["controls"]:controls(args[1] if len(args)>1 else None)
    elif args[:1]==["deep"]:deep(args[1] if len(args)>1 else None)
    elif args[:1]==["expansions"]:expansions(args[1] if len(args)>1 else None)
    elif args[:1]==["limits"]:limits(args[1] if len(args)>1 else None)
    elif args[:1]==["auth"]:auth(args[1] if len(args)>1 else None)
    elif args[:1]==["strict"]:strict_raw(args[1] if len(args)>1 else None)
    elif args==["preprocessing"]:preprocessing()
    elif args[:1]==["ordering"]:
        result=subprocess.run([str(TEST),"--move-ordering",args[1] if len(args)>1 else ""],capture_output=True,timeout=30)
        sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
        return result.returncode
    elif args==["history"]:
        from evidence_history import selftest
        selftest()
    elif args==["refusals"]:refusals()
    elif args==["fifo"]:fifo()
    elif args==["injected"]:
        result=subprocess.run([str(TEST),"--move-injected"],capture_output=True,timeout=30)
        sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
        return result.returncode
    elif not args:
        replay();controls();refusals();deep();expansions();limits();auth();fifo();strict_raw();preprocessing()
    else:raise AssertionError("move test selector")
    return 0


if __name__=="__main__":sys.exit(main())
