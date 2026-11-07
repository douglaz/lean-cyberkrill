#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Guarded fiat commands: synthetic TLS feeds, exact RPC selectors, recorded PSBTs."""
from contextlib import contextmanager, chdir
from decimal import Decimal
from fractions import Fraction
import importlib
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile

from cases import APP, ROOT
from compare import exact_json
import network
C = importlib.import_module("rpc-client")
G, R = C.G, C.R
P = importlib.import_module("price-feeds")
SOURCES = P.C.SOURCES
EXE = APP / ".lake/build/bin/CyberkrillTests"


def converted(amount, mode, price="100000000"):
    """Independent rational derivation: msat rounding BEFORE flag precision."""
    n = Fraction(amount) / Fraction(price) * 10**11
    msat = (2*n.numerator+n.denominator)//(2*n.denominator)
    return (msat+500)//1000 if mode == "whole" else msat//1000


def body(price):
    return dict(bitcoin=dict(usd=price, brl=price, inr=price),
                data=dict(rates=dict(USD=price, BRL=price, INR=price)),
                USD=dict(last=price), BRL=dict(last=price), INR=dict(last=price),
                result=dict(PAIR=dict(c=[price])), last=price, rate=price,
                prices={"BTC/USD":dict(rate=price), "BRL/USD":dict(rate=1), "INR/USD":dict(rate=1)})


@contextmanager
def feeds(root, entries):
    spec = root / "feeds.json"; spec.write_text(json.dumps(dict(entries=entries)))
    log = root / "feeds.requests"
    with (root / "feeds.stderr").open("wb") as errors:
        child = subprocess.Popen([sys.executable, "-B", str(ROOT / "packages/http-curl/test/responder.py"),
            str(spec), "--log", str(log), "--tls", "--cert", str(root / "cert.pem"), "--key", str(root / "key.pem")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        handlers = {}
        def interrupted(signum, _frame): raise SystemExit(128+signum)
        try:
            for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]:
                handlers[sig] = signal.signal(sig, interrupted)
            assert select.select([child.stdout], [], [], 10)[0], "fiat TLS responder startup"
            ready = child.stdout.readline().decode().split()
            assert len(ready) == 3 and ready[0] == "READY", "fiat TLS responder READY"
            port = int(ready[1]); assert 0 < port < 65536 and port != 8332
            yield "https://127.0.0.1:"+str(port), log
        finally:
            for sig in handlers: signal.signal(sig, signal.SIG_IGN)
            try:
                child.stdin.close()
                child.wait(timeout=5)
                child.stdout.close()
                assert child.returncode == 0, "fiat TLS responder reaped"
            finally:
                for sig, handler in handlers.items(): signal.signal(sig, handler)


def matrix():
    rows = []
    for funded in [False, True]:
        prefix = "funded" if funded else "create"
        for name, text, sats in [
            ("fiat", "a:12USD", [12]), ("mixed", "a:12USD,b:3sat", [12,3]),
            ("below", "a:1.499499USD", [1]), ("at", "a:1.4995USD", [2]),
            ("above", "a:1.499501USD", [2]), ("zero", "a:0USD", [0]),
            ("tiny-edge", "a:0.4995USD", [1]),
            ("normalized", "a:1usd,b:2USD,c:3uSd", [1,2,3]),
            ("currencies", "a:1usd,b:2BRL,c:3brl", [1,2,3]),
            ("duplicates", "a:1usd,a:2USD", [2]),
            ("duplicate-currencies", "a:1USD,a:2BRL", [2]),
            ("grouped", "a:1,234USD,b:12,34,567INR", [1234,1234567]),
            ("exponent", "a:1e2USD", [100]), ("whitespace", " a : 12USD\u00a0,b:3sat ", [12,3]),
            ("bitcoin", "a:.5,b:5.,c:+1sat,d:-0.0btc", [50000000,500000000,1,0]),
            ("files", "a:12USD", [12]), ("alias", "a:12USD", [12]),
        ]:
            rows.append(dict(name=prefix+"-"+name, funded=funded, outputs=text, sats=sats))
        for name, text, error, currencies in [
            ("tiny-msat", "a:0.0000001USD", "less than 1 msat", ["USD"]),
            ("tiny-sat", "a:0.499499USD", "lessThanOneSat:", ["USD"]),
            ("range", "a:1e30USD", "outside the supported range", ["USD"]),
            ("malformed", "a:+1USD", "invalidFiat:", []),
            ("later-malformed", "a:1USD,broken", "invalidOutputs:", []),
            ("later-precision", "a:1USD,b:1msat", "wholeSatRequired:", []),
            ("duplicate-invalid", "a:0.1USD,a:2USD", "lessThanOneSat:", ["USD"]),
            ("trailing", "a:1USD,", "invalidOutputs:", []),
            ("grouped-exponent", "a:1,234.5e2USD", "invalidOutputs:", []),
            ("scanner-space", "a:1,234\u00a0USD", "invalidOutputs:", []),
            ("quorum", "a:1USD", "need at least 3", ["USD"]),
            ("last-colon", "a:b:1USD", "invalidOutputs:", ["USD"]),
        ]:
            rows.append(dict(name=prefix+"-"+name, funded=funded, outputs=text, error=error, currencies=currencies))
    for name, cap, selected in [
        ("below", "100.999499USD", 1), ("at", "100.9995USD", 2), ("above", "100.999501USD", 2),
        ("floor", "100.75USD", 1), ("overshoot", "101USD", 2), ("bitcoin", "100.999sat", 1),
        ("files", "101USD", 2), ("alias", "101USD", 2), ("grouped", "1,234USD", 2),
    ]:
        rows.append(dict(name="move-"+name, cap=cap, selected=selected))
    for name, cap, error, currencies in [
        ("zero", "0USD", "emptySelection:", ["USD"]),
        ("tiny-msat", "0.0000001USD", "less than 1 msat", ["USD"]),
        ("tiny-sat", "0.999499USD", "lessThanOneSat:", ["USD"]),
        ("range", "1e30USD", "outside the supported range", ["USD"]),
        ("malformed", "+1USD", "invalidNumber:", []),
        ("quorum", "1USD", "need at least 3", ["USD"]),
    ]:
        rows.append(dict(name="move-"+name, cap=cap, error=error, currencies=currencies))
    assert len(rows) == 73, "fiat command matrix inventory"
    return rows


def currencies(row):
    if "currencies" in row: return row["currencies"]
    if "bitcoin" in row["name"]: return []
    if "currencies" in row["name"]: return ["USD", "BRL"]
    if row["name"].endswith("grouped") and "outputs" in row: return ["USD", "INR"]
    return ["USD"]


def breadcrumb(currency):
    return f"[price-feed] median BTC/{currency} = 100000000.00 from 9 feeds: " + ", ".join(sorted(SOURCES)) + "\n"


def replay(only=None):
    assert network.sandbox() or network.isolated(), "fiat command isolation"
    parent = APP / ".lake/fiat-onchain"; parent.mkdir(parents=True, exist_ok=True)
    provenance = json.loads((APP/"test/fiat-onchain-provenance.json").read_text())
    assert provenance["revision"] == "27cad1faba86260b06665a89f0af5134d23525c2", "fiat reference authority"
    for path,digest in provenance["fixture_sha256"].items():
        assert hashlib.sha256((APP/"test"/path).read_bytes()).hexdigest()==digest, "fiat pinned fixture binding "+path
    importlib.import_module("capture-fiat-onchain-reference").verify()
    R.fiat_capture_attempts()
    rows = matrix()
    if only:
        rows = [r for r in rows if r["name"] == ("create-fiat" if only == "lifetime" else only)]
        assert len(rows) == 1, "fiat selected matrix case"
    # Exact helper checks also bind the chosen two-stage command boundaries.
    assert [converted(x,"whole") for x in ["1.499499","1.4995","1.499501"]] == [1,2,2]
    assert [converted(x,"floor") for x in ["100.999499","100.9995","100.999501"]] == [100,101,101]
    with tempfile.TemporaryDirectory(dir=parent) as temporary:
        root = Path(temporary); home = root / "home"; home.mkdir()
        cert = network.run_owned(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(root/"key.pem"),
            "-out",str(root/"cert.pem"),"-days","1","-subj","/CN=localhost","-addext","subjectAltName=IP:127.0.0.1"],capture_output=True,timeout=30)
        assert cert.returncode == 0, "fiat TLS certificate"+cert.stderr.decode()
        entries = []
        for row in rows:
            paths = {path.replace("usd",c.lower()).replace("USD",c) for c in ["USD","BRL","INR"] for path in P.C.PATHS}
            for path in paths:
                entries.append(dict(method="GET",path="/"+row["name"]+path,
                    responses=[dict(status=200,json={} if row["name"].endswith("quorum") else body("100000000"))],repeat=True))
        fixture = R.parse_json((APP/"test/recordings/fiat-create.json").read_bytes())
        psbt = R.result(fixture["entries"][-1])
        requests = []; payload = []; expected = []
        for row in rows:
            name = row["name"]; path = "/"+name
            argv = ["onchain-move-utxos" if "cap" in row else "onchain-create-funded-psbt" if row["funded"] else "onchain-create-psbt",
                    "--network","regtest","--inputs","synthetic-a:0"]
            wanted = []
            if "cap" in row:
                argv += ["--inputs","synthetic-b:1","--destination","destination","--fee","1sat","--max-amount",row["cap"]]
                for txid,index,sats in [("synthetic-a",0,100),("synthetic-b",1,60)]:
                    params = [txid,True]; wanted.append(["getrawtransaction",params])
                    requests.append(dict(method="POST",path=path,rpc=dict(method="getrawtransaction",params=[params]),
                        responses=[dict(status=200,json=dict(result=dict(vout=[dict(value=0),dict(value=0)] if index else [dict(value=Decimal(sats)/100000000)])))]))
                    if index: requests[-1]["responses"][0]["json"]["result"]["vout"][1]["value"] = Decimal(sats)/100000000
                inputs = [dict(txid="synthetic-a",vout=0),dict(txid="synthetic-b",vout=1)][:row.get("selected",0)]
                outputs = dict(destination=Decimal(99 if len(inputs)==1 else 159)/100000000)
                method = "createpsbt"; options = False; result = dict(psbt=psbt,fee_sats=1,change_position=None)
            else:
                argv += ["--outputs",row["outputs"]]
                inputs = [dict(txid="synthetic-a",vout=0)]
                keys = [entry.rsplit(":",1)[0].strip() for entry in ["a:1","b:1","c:1","d:1"]][:len(row.get("sats",[]))]
                outputs = dict(zip(keys,[Decimal(v)/100000000 for v in row.get("sats",[])]))
                method = "walletcreatefundedpsbt" if row["funded"] else "createpsbt"; options = {} if row["funded"] else False
                result = dict(psbt=psbt,fee_sats=2 if row["funded"] else 0,change_position=1 if row["funded"] else None)
            params = [inputs,outputs,0] if row.get("funded") else [inputs,outputs,0,options]
            if not row.get("error"):
                wanted.append([method,params])
                reply = dict(psbt=psbt,fee=Decimal(2)/100000000,changepos=1) if row.get("funded") else psbt
                requests.append(dict(method="POST",path=path,rpc=dict(method=method,params=[params]),responses=[dict(status=200,json=dict(result=reply))]))
            if row.get("error") and not name.endswith("zero") and not name.endswith("last-colon"): wanted = []
            if name.endswith("last-colon"): wanted = []
            # File and alias behavior uses real filesystem writers in the owned HOME.
            if name.endswith(("files","alias")):
                row["file"] = str(home/(name+".json")); row["raw"] = row["file"] if name.endswith("alias") else str(home/(name+".psbt"))
                argv += ["--output",row["file"],"--psbt-output",row["raw"]]
            payload.append(dict(args=argv,rpc_path=path,feeds_path="/"+name))
            expected.append((wanted,result))
        for entry in requests: entry["repeat"] = True
        spec = root/"rpc.json"; spec.write_text(G.json_text(dict(entries=requests)))
        with feeds(root,entries) as (base,feed_log), C.responder(spec) as (rpc,rpc_log,_):
            for value in payload:
                value["feeds"] = [base+value.pop("feeds_path")]*9
                value["rpc"] = rpc+value.pop("rpc_path")
                value["args"] += ["--rpc-url",value["rpc"]]
            # A later command in this SAME process must acquire another quote.
            for index in ([0] if only == "lifetime" else [] if only else [0,29,58]):
                payload.append(payload[index]); rows.append(rows[index]); expected.append(expected[index])
            env = dict(os.environ,HOME=str(home),TMPDIR=str(root),SSL_CERT_FILE=str(root/"cert.pem"),PYTHONDONTWRITEBYTECODE="1")
            # run_owned has no stdin argument; the existing test executable invocation is bounded and owned by this isolated driver.
            proc = subprocess.run([str(EXE),"--fiat-onchain-run"],input=json.dumps(payload).encode(),cwd=home,env=env,capture_output=True,timeout=180)
            assert proc.returncode == 0 and not proc.stderr, "fiat guarded process: "+proc.stderr.decode()
            results = exact_json(proc.stdout); assert len(results)==len(rows)==(2 if only == "lifetime" else 1 if only else 76), "fiat guarded result count"
            logged = C.logged(rpc_log); feeds_logged = C.logged(feed_log)
            for row, actual, (wanted,result) in zip(rows,results,expected):
                name = row["name"]
                if row.get("error"):
                    assert actual["status"]==1 and not actual["stdout"] and row["error"] in actual["stderr"], "fiat command refusal "+name+": "+repr(actual)
                else:
                    assert actual["status"]==0, "fiat command success "+name+": "+repr(actual)
                    output = Path(row["file"]).read_text() if "file" in row else actual["stdout"]
                    assert exact_json(output)==result and not output.endswith("\n"), "fiat complete JSON "+name
                    assert bool(actual["stdout"]) == ("file" not in row), "fiat file stdout "+name
                    if "raw" in row and row["raw"]!=row["file"]: assert Path(row["raw"]).read_text()==psbt, "fiat raw bytes "+name
                count = sum(r["name"]==name for r in rows)
                actual_requests = [[R.parse_json(x["body"])["method"],R.parse_json(x["body"])["params"]] for x in logged if x["path"]=="/"+name]
                assert G.selector(actual_requests)==G.selector(wanted*count), "fiat ordered RPC "+name+": "+repr(actual_requests)
                early = bool(row.get("error")) and not name.endswith(("zero","last-colon"))
                assert actual["clients"]==(0 if early else 1), "fiat client boundary "+name
                quotes = currencies(row)
                observed = [x for x in feeds_logged if x["path"].startswith("/"+name+"/")]
                assert len(observed)==9*len(quotes)*count, "fiat command cache requests "+name+": "+str(len(observed))
                if name.endswith("quorum"):
                    assert "[price-feed] median" not in actual["stderr"], "fiat failed quorum breadcrumb"
                else:
                    prefix = "".join(breadcrumb(c) for c in quotes)
                    assert actual["stderr"].startswith(prefix) and actual["stderr"].count("[price-feed] median")==len(quotes), "fiat breadcrumbs "+name
                    if not row.get("error"): assert actual["stderr"]==prefix, "fiat success stderr "+name
            print("fiat onchain selected control passed" if only else "fiat onchain guarded matrix: 29/29 create, 29/29 funded, 15/15 move; 3/3 same-process fresh quotes; 76/76 invocations",flush=True)
        if not only: recorded(root)


def recorded(root):
    """Real newly generated replies and complete source-derived command JSON."""
    fixtures = json.loads((APP/"test/http/success.json").read_text())
    for name in ["fiat-create","fiat-funded"]:
        data = R.parse_json((APP/"test/recordings"/(name+".json")).read_bytes())
        final = data["entries"][-1]; params = final["rpc"]["params"][0]; funded = name=="fiat-funded"
        entries = [dict(method="GET",path=path,responses=[dict(status=200,json=fixtures[source])],repeat=True) for source,path in zip(SOURCES,P.C.PATHS)]
        sub = root/name;sub.mkdir(); (sub/"cert.pem").write_bytes((root/"cert.pem").read_bytes());(sub/"key.pem").write_bytes((root/"key.pem").read_bytes())
        with feeds(sub,entries) as (base,log), C.responder(APP/"test/recordings"/(name+".json")) as (rpc,rpclog,_):
            args = ["onchain-create-funded-psbt" if funded else "onchain-create-psbt","--network","regtest","--inputs",data["entries"][0]["rpc"]["params"][0][0],
                "--outputs",next(iter(params[1]))+":95.04USD","--fee-rate","1sat","--rpc-url",rpc+"/wallet/single","--rpc-user","lck","--rpc-password","lck-throwaway"]
            env = dict(os.environ,HOME=str(root/"home"),TMPDIR=str(root),SSL_CERT_FILE=str(root/"cert.pem"))
            proc = subprocess.run([str(EXE),"--fiat-onchain-run"],input=json.dumps([dict(args=args,feeds=[base]*9,rpc=rpc)]).encode(),env=env,cwd=root/"home",capture_output=True,timeout=45)
            assert proc.returncode==0 and not proc.stderr, "fiat recorded process"
            actual = exact_json(proc.stdout)[0]; reply = R.result(final)
            # bitcoin_rpc.rs:982-997 weight: 4 inputs, 1 output, rate 1sat/vB.
            expected = dict(psbt=reply["psbt"] if funded else reply,fee_sats=int(reply["fee"]*100000000) if funded else 314,change_position=reply["changepos"] if funded else None)
            assert actual["status"]==0 and exact_json(actual["stdout"])==expected, "fiat recorded complete JSON "+name+": "+repr(actual)
            assert not actual["stdout"].endswith("\n") and actual["clients"]==1 and len(C.logged(log))==9, "fiat recorded streams/requests"
            observed = [[R.parse_json(x["body"])["method"],R.parse_json(x["body"])["params"]] for x in C.logged(rpclog)]
            assert G.selector(observed)==G.selector([[e["rpc"]["method"],e["rpc"]["params"][0]] for e in data["entries"]]), "fiat recorded ordered exact RPC"
    print("fiat new Core recordings: 2/2 commands, 24/24 ordered selectors; complete derived JSON",flush=True)


if __name__ == "__main__":
    if sys.argv[1:2]==["--isolated"]: replay(sys.argv[2] if len(sys.argv)>2 else None)
    else:
        assert not sys.argv[1:] or (len(sys.argv)==3 and sys.argv[1]=="--probe")
        sys.exit(network.run_isolated([sys.executable,"-B",str(Path(__file__).resolve()),"--isolated",*sys.argv[2:]],timeout=240))
