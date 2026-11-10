#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Isolated LNURL-pay replay; independent exact output and raw request assertions."""
from contextlib import contextmanager, chdir
from copy import deepcopy
from fractions import Fraction
import hashlib
import importlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cases import APP, ROOT
from compare import exact_json
import network

PORT = 19443
BASE = "https://127.0.0.1:" + str(PORT)
ADDRESS = "user@127.0.0.1:" + str(PORT)
WELL_KNOWN = "/.well-known/lnurlp/user"
EXE = APP / ".lake/build/bin/cyberkrill"
TEST = APP / ".lake/build/bin/CyberkrillTests"
P = importlib.import_module("price-feeds")
F = importlib.import_module("fiat-onchain")


def fixtures():
    provenance = json.loads((APP/"test/http/ln-generate.provenance.json").read_text())
    for path, digest in provenance["sha256"].items():
        assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest() == digest, "LNURL fixed provenance " + path
    return (json.loads((APP/"test/http/ln-generate.json").read_text()),
            exact_json((APP/"test/http/ln-generate-expected.json").read_text()))


def cases():
    rows = [dict(name=name, amount=amount, msat=msat) for name,amount,msat in [
        ("sats","2sats",2000), ("minimum","1sat",1000), ("maximum","3sat",3000),
        ("msat","2001msat",2001), ("btc","0.00000002btc",2000)]]
    rows += [dict(name="below",amount="999msat",error="outside allowed range",requests=1),
             dict(name="above",amount="3001msat",error="outside allowed range",requests=1)]
    rows += [dict(name=name,comment=comment) for name,comment in [
        ("empty",""), ("unicode","a + café"), ("byte-boundary","é"*8)]]
    rows += [dict(name="byte-over",comment="é"*8+"a",error="Comment length 17",requests=1),
             dict(name="no-limit",comment="é"*20,limit=False),
             dict(name="null-limit",comment="é"*20,limit=None),
             dict(name="zero-limit-empty",comment="",limit=0),
             dict(name="zero-limit-over",comment="x",limit=0,error="Comment length 1",requests=1),
             dict(name="malformed-address",address="malformed",error="malformedAddress",requests=0),
             dict(name="error",well_error=True,error="malformedResponse",requests=1),
             dict(name="callback-error",callback_error=True,error="malformedResponse",requests=2),
             dict(name="invalid-invoice",invoice="invalid",error="missingSeparator",requests=2),
             dict(name="bad-callback",callback="https://[::1]/pay",error="unsupportedUrlForm",requests=1),
             dict(name="normalize",callback="HTTPS://127.0.0.1:019443/a/../pay path?dup=first&dup=last&flag#frag ment",
                  path="/pay%20path?dup=first&dup=last&flag",comment="a + café"),
             dict(name="permissive",tag="unchecked-tag",status=503,metadata="not nested JSON"),
             dict(name="file",file=True),
             dict(name="late-file-failure",file=True,amount="invalid",error="invalidNumber:",requests=0),
             dict(name="open-failure",file="directory",inprocess=True,amount="1USD",error="outputFailure:",requests=0),
             dict(name="delay",delay=3000,error="timeout",requests=1),
             dict(name="oversize",oversize=True,error="tooLarge",requests=1),
             dict(name="tls-untrusted",untrusted=True,error="tls",requests=0)]
    rows += [dict(name="fiat-"+name,amount=amount,msat=msat,fiat=True) for name,amount,msat in [
        ("below","2.000499USD",2000), ("at","2.0005USD",2001), ("above","2.000501USD",2001)]]
    rows += [dict(name="fiat-quorum",fiat=True,amount="2USD",quorum=True,error="need at least 3",requests=0),
             dict(name="fiat-tiny",fiat=True,amount="0.0000001USD",error="less than 1 msat",requests=0),
             dict(name="fiat-lifetime",fiat=True,amount="2USD",repeat=2),
             dict(name="bitcoin-inprocess",inprocess=True)]
    rows += [dict(name="comment-short-equals",comment="x=y",comment_flag="-c"),
             dict(name="comment-long-equals",comment="a + café",comment_flag="--comment="),
             dict(name="output-short-equals",file=True,output_flag="-o"),
             dict(name="new-file-failure",file=True,new_file=True,amount="invalid",error="invalidNumber:",requests=0),
             dict(name="late-range-file",file=True,amount="999msat",error="outside allowed range",requests=1),
             dict(name="open-handle",file=True,inprocess=True,replace=True),
             dict(name="write-failure",file="full",error="outputFailure:",requests=2)]
    rows.append(dict(name="trailing-query",callback=BASE+"/pay?dup=first&dup=last&flag&#fragment",
                     path="/pay?dup=first&dup=last&flag&"))
    rows += [dict(name="address-space",address="user name@127.0.0.1:"+str(PORT),
                  well_path="/.well-known/lnurlp/user%20name"),
             dict(name="address-space-inprocess",address="user name@127.0.0.1:"+str(PORT),
                  well_path="/.well-known/lnurlp/user%20name",inprocess=True)]
    rows += [dict(name="redirect-well-"+str(status),well_redirect=status,
                  comment="a + café") for status in [301,302,303,307,308]]
    rows += [dict(name="redirect-callback",callback_redirect=307,comment="a + café"),
             dict(name="redirect-limit",well_redirect=302,loop=True,error="redirectLimit",requests=11),
             dict(name="redirect-ten",well_redirect=302,chain=10),
             dict(name="redirect-missing-location",status=302),
             dict(name="redirect-invalid-location",status=302,location="/bad path"),
             dict(name="redirect-nonstatus",status=300,location="/unvisited"),
             dict(name="redirect-unsafe",well_redirect=302,location="https://external.invalid/pay",
                  inprocess=True,error="Test LNURL target refused",requests=1),
             dict(name="redirect-unsupported",well_redirect=302,location="https://[::1]/pay",
                  error="unsupportedUrlForm",requests=1)]
    rows += [dict(name="redirect-invalid-path",status=302,location="/bad[x]"),
             dict(name="redirect-invalid-query",status=302,location="/pay?q=[x]"),
             dict(name="redirect-invalid-port",status=302,location="https://127.0.0.1:bad/pay")]
    rows.append(dict(name="redirect-raw-query",callback_redirect=307,
                     redirect_target="/finished?amount=2000&note='raw'",
                     redirect_location="./keep/%2e%2e/finished?amount=2000&note='raw'"))
    rows.append(dict(name="guard-invalid-initial",inprocess=True,address="user@é.example",amount="invalid",
                     file=True,guard_file=True,error="testLnurlRefused:",requests=0))
    # Raw numeric tokens exercise the preflight before Json.parse, including
    # otherwise ignored fields. Strings with the same text must stay strings.
    for side, requests in [("well", 1), ("callback", 2)]:
        for name, token in [("huge", "1e1000000000"), ("tiny", "1e-1000000000"),
                            ("zero", "0e1000000000"), ("numeric-limit", "1e1025")]:
            rows.append(dict(name=side+"-"+name, **{side+"_number":token},
                             error="malformedResponse: JSON", requests=requests))
    rows += [dict(name="well-long-exponent",well_number="1e"+"9"*2100,
                  error="malformedResponse: JSON",requests=1),
             dict(name="well-long-coefficient",well_number="1"*1025,
                  error="malformedResponse: JSON",requests=1),
             dict(name="well-coefficient-boundary",well_number="1"*1024),
             dict(name="well-exponent-boundary",well_number="1e1024"),
             dict(name="well-numeric-string",well_string="1e1000000000\\\"tail"),
             dict(name="callback-numeric-string",callback_string="1e-1000000000")]
    assert len(rows) == 77, "LNURL matrix inventory"
    return rows


def form(text):
    # Independently specified form encoding, never imports the Lean serializer.
    return "".join("+" if b == 32 else chr(b) if b in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*-._" else f"%{b:02X}" for b in text.encode())


@contextmanager
def responder(root, entries, *, collision=False):
    spec = root/"responses.json"; spec.write_text(json.dumps(dict(entries=entries)))
    log = root/"requests.jsonl"
    # Use the existing responder and ownership protocol; delay only the selected
    # recorded reply, after its actual request has been logged.
    program = '''import importlib.util,sys,time
spec=importlib.util.spec_from_file_location("responder",sys.argv.pop(1))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original=m.Handler.send_recorded
def send(self,response):
 time.sleep(int(response.get("delay_ms",0))/1000)
 original(self,response)
m.Handler.send_recorded=send
m.main()
'''
    with (root/"responder.stderr").open("wb") as errors:
        child = subprocess.Popen([sys.executable,"-B","-c",program,str(ROOT/"packages/http-curl/test/responder.py"),
            str(spec),"--port",str(PORT),"--log",str(log),"--tls","--cert",str(root/"cert.pem"),"--key",str(root/"key.pem")],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,cwd=root,
            env=dict(os.environ,TMPDIR=str(root),HOME=str(root/"home"),PYTHONDONTWRITEBYTECODE="1"))
        handlers = {}
        def interrupted(signum, _frame): raise SystemExit(128+signum)
        try:
            for sig in [signal.SIGHUP,signal.SIGINT,signal.SIGQUIT,signal.SIGTERM]:
                handlers[sig] = signal.signal(sig,interrupted)
            assert select.select([child.stdout],[],[],10)[0], "LNURL responder startup"
            ready = child.stdout.readline().decode().split()
            if collision:
                assert not ready and child.wait(timeout=5) != 0, "LNURL fixed-port collision refused"
            else:
                assert len(ready)==3 and ready[0]=="READY" and int(ready[1])==PORT and child.poll() is None, "LNURL owned fixed-port READY"
            yield log
        finally:
            for sig in handlers: signal.signal(sig,signal.SIG_IGN)
            try:
                child.stdin.close(); child.wait(timeout=5); child.stdout.close()
                assert child.returncode == (1 if collision else 0), "LNURL responder reaped"
            finally:
                for sig,handler in handlers.items(): signal.signal(sig,handler)
    if not collision:
        assert not (root/"responder.stderr").read_bytes(), "LNURL responder unmatched/exhausted reply"


def request_path(row):
    prefix = row.get("path", "/pay?dup=first&dup=last&flag")
    return prefix+"&amount="+str(row.get("msat",2000))+("&comment="+form(row["comment"]) if "comment" in row else "")


def replay(only=None):
    assert network.sandbox() or network.isolated(), "LNURL replay isolation"
    fixture, expected = fixtures()
    rows = cases()
    if only:
        rows = [r for r in rows if r["name"]==only]
        assert len(rows)==1, "LNURL selected case"
    parent = APP/".lake/ln-generate"; parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as temporary:
        root = Path(temporary); (root/"home").mkdir()
        environment = dict(os.environ,HOME=str(root/"home"),TMPDIR=str(root),SSL_CERT_FILE=str(root/"cert.pem"),PYTHONDONTWRITEBYTECODE="1")
        proc = network.run_owned(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(root/"key.pem"),
            "-out",str(root/"cert.pem"),"-days","1","-subj","/CN=localhost","-addext","subjectAltName=IP:127.0.0.1"],env=environment,capture_output=True,timeout=30)
        assert proc.returncode==0, "LNURL synthetic TLS certificate"
        for row in rows:
            name = row["name"]; count = row.get("repeat",1)
            pay = deepcopy(fixture["well_known"])
            if "limit" in row:
                if row["limit"] is False: del pay["commentAllowed"]
                else: pay["commentAllowed"] = row["limit"]
            for field in ["callback","tag","metadata"]:
                if field in row: pay[field] = row[field]
            callback = deepcopy(fixture["callback"])
            if "invoice" in row: callback["pr"] = row["invoice"]
            well_path = row.get("well_path",WELL_KNOWN)
            entries = [dict(method="GET",path=well_path,responses=[dict(status=row.get("status",200),
                json=fixture["error"] if row.get("well_error") else pay,delay_ms=row.get("delay",0))],repeat=True),
                dict(method="GET",path=request_path(row),responses=[dict(status=row.get("status",200),
                json=fixture["error"] if row.get("callback_error") else callback)],repeat=True)]
            for side, entry in [("well", entries[0]), ("callback", entries[1])]:
                if side+"_string" in row:
                    entry["responses"][0]["json"]["ignored"] = row[side+"_string"]
                if side+"_number" in row:
                    response = entry["responses"][0]
                    text = json.dumps(response.pop("json"))
                    response["text"] = text[:-1] + ',"ignored":' + row[side+"_number"] + '}'
            paths = [well_path,request_path(row)][:row.get("requests",2)]
            if "location" in row and not row.get("well_redirect"):
                for entry in entries: entry["responses"][0]["headers"] = {"Location":row["location"]}
            if row.get("well_redirect"):
                location = row.get("location",BASE+"/redirected/well")
                entries[0]["responses"] = [dict(status=row["well_redirect"],headers={"Location":location},text="")]
                if row.get("loop"):
                    entries[0]["responses"][0]["headers"]["Location"] = "user"
                    paths = [well_path]*11
                elif row.get("chain"):
                    # Policy::limited(10) follows ten hops: eleven total GETs.
                    entries[0]["responses"][0]["headers"]["Location"] = "/hop/1"
                    for hop in range(1,11):
                        response = dict(json=pay) if hop==10 else dict(status=302,headers={"Location":str(hop+1)},text="")
                        entries.append(dict(method="GET",path="/hop/"+str(hop),responses=[response]))
                    paths = [well_path]+["/hop/"+str(hop) for hop in range(1,11)]+[request_path(row)]
                elif "error" not in row:
                    entries.append(dict(method="GET",path="/redirected/well",responses=[dict(json=pay)]))
                    paths = [well_path,"/redirected/well",request_path(row)]
            if row.get("callback_redirect"):
                # Resolve against /pay?...; do not append amount/comment again.
                target = row.get("redirect_target","/finished?amount=2000&comment=a+%2B+caf%C3%A9")
                location = row.get("redirect_location","./middle/../"+target[1:])
                entries[1]["responses"] = [dict(status=row["callback_redirect"],headers={"Location":location},text="")]
                entries.append(dict(method="GET",path=target,responses=[dict(json=callback)]))
                paths = [well_path,request_path(row),target]
            if row.get("oversize"): entries[0]["responses"] = [dict(text="x"*1048577)]
            entries += [dict(method="GET",path=path,responses=[dict(json={} if row.get("quorum") else F.body("100000000"))],repeat=True) for path in P.C.PATHS]
            output = root/"output=value.json"
            output.write_text("existing bytes")
            if row.get("new_file"): output.unlink()
            args = ["ln-generate-invoice",row.get("address",ADDRESS),row.get("amount","2sat")]
            if "comment" in row:
                if "comment_flag" in row: args += [row["comment_flag"]+row["comment"]]
                else: args += ["-c",row["comment"]]
            if row.get("file"):
                target = root if row["file"]=="directory" else output
                if row["file"]=="full":
                    target = root/"full"; target.symlink_to("/dev/full")
                if "output_flag" in row: args += [row["output_flag"]+str(target)]
                else: args += ["-o",str(target)]
            env = dict(environment)
            if row.get("untrusted"): env["SSL_CERT_FILE"] = str(root/"missing-ca.pem")
            with responder(root,entries) as log:
                start = time.monotonic()
                if row.get("fiat") or row.get("inprocess"):
                    payload = [dict(args=args,feeds=[BASE]*9,replace=row.get("replace",False))]*count
                    proc = subprocess.run([str(TEST),"--generate-invoice-run"],input=json.dumps(payload).encode(),env=env,cwd=root/"home",capture_output=True,timeout=30)
                    assert proc.returncode==0 and not proc.stderr, "LNURL guarded batch process: "+proc.stderr.decode()
                    results = exact_json(proc.stdout); assert len(results)==count, "LNURL batch count"
                else:
                    network.refuse_spawn(args,BASE)
                    proc = subprocess.run([str(EXE),*args],env=env,cwd=root/"home",stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
                    results = [dict(status=proc.returncode,stdout=proc.stdout.decode(),stderr=proc.stderr.decode())]
                elapsed = time.monotonic()-start
                for result in results:
                    if "error" in row:
                        assert result["status"]==1 and not result["stdout"] and row["error"] in result["stderr"], "LNURL refusal "+name+": "+repr(result)
                        if row.get("file") is True:
                            wanted_file = b"existing bytes" if row.get("guard_file") else b""
                            assert output.read_bytes()==wanted_file, "LNURL guarded file preservation" if row.get("guard_file") else "LNURL late file truncation"
                    else:
                        observed = [json.loads(line)["path"] for line in log.read_text().splitlines()] if log.exists() else []
                        assert result["status"]==0, "LNURL success "+name+": "+repr(result)+"; observed paths="+repr(observed)
                        if row.get("replace"):
                            assert output.read_text()=="replacement leaf", "LNURL retained output leaf"
                        text = (Path(str(output)+".opened") if row.get("replace") else output).read_text() if row.get("file") else result["stdout"]
                        wanted = dict(expected,lightning_address=row.get("address",ADDRESS),amount_msats=row.get("msat",2000),comment=row.get("comment"))
                        assert exact_json(text)==wanted, "LNURL complete JSON "+name
                        assert "\n" in text and not text.endswith("\n"), "LNURL pretty/no-newline "+name
                        assert bool(result["stdout"]) != bool(row.get("file")), "LNURL file/stdout "+name
                    if row.get("fiat") and not row.get("quorum"):
                        assert result["stderr"].startswith(F.breadcrumb("USD")), "LNURL fiat breadcrumb "+name
                    elif "error" not in row: assert not result["stderr"], "LNURL success stderr "+name
                logged = [json.loads(s) for s in log.read_text().splitlines()] if log.exists() else []
                lnurl = [r for r in logged if r["path"] not in P.C.PATHS]
                wanted_paths = paths*count
                assert [r["path"] for r in lnurl]==wanted_paths, "LNURL ordered requests "+name+": "+repr(lnurl)
                assert all(r["method"]=="GET" and r["body"]=="" for r in logged), "LNURL GET only "+name
                feeds = [r["path"] for r in logged if r["path"] in P.C.PATHS]
                assert sorted(feeds)==sorted(P.C.PATHS*count if row.get("fiat") else []), "LNURL price requests "+name
                if row.get("delay"):
                    assert 1.5 <= elapsed < 5, "LNURL tested delayed response bound"
                    print("LNURL 3000ms delayed response: timeout after configured 2000ms; observed under 5s",flush=True)
            log.unlink(missing_ok=True)
        if not only:
            with socket.socket() as occupied:
                occupied.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                occupied.bind(("127.0.0.1",PORT)); occupied.listen()
                with responder(root,[],collision=True): pass
            guards(root,environment)
            parser(root,environment)
            path_stress(environment)
    print("LNURL selected control passed" if only else "LNURL replay: 77/77 cases, 78/78 invocations; exact five-field JSON, ordered GETs and no early callback; collision 1/1",flush=True)


def guards(root, env):
    refused = [["ln-generate-invoice","user@external.invalid","1sat"],
               ["ln-generate-invoice",ADDRESS,"1USD"],
               ["ln-generate-invoice","user@127.0.0.1:8332","1sat"],
               ["ln-generate-invoice","user%2540external.invalid@127.0.0.1:"+str(PORT),"1sat"],
               ["ln-generate-invoice","user@127.0.0.1", "1sat"],
               ["ln-generate-invoice","user@127.0.0.1:"+str(PORT)+"\\external.invalid", "1sat"]]
    for args in refused:
        try: network.refuse_spawn(args,BASE)
        except ValueError: pass
        else: raise AssertionError("LNURL pre-spawn guard")
    payload = [dict(args=["ln-generate-invoice","user@external.invalid","2USD"],feeds=[BASE]*9)]
    proc = subprocess.run([str(TEST),"--generate-invoice-run"],input=json.dumps(payload).encode(),env=env,cwd=root/"home",capture_output=True,timeout=10)
    assert proc.returncode==0 and not proc.stderr, "LNURL inprocess guard setup"
    result = exact_json(proc.stdout)[0]
    assert result["status"]==1 and not result["stdout"] and result["stderr"].startswith("testLnurlRefused:"), "LNURL inprocess guard before action"
    proc = network.run_owned([str(TEST),"--generate-invoice-ordering"],env=env,capture_output=True,timeout=10)
    assert proc.returncode==0, "LNURL injected ordering: "+proc.stderr.decode()
    print("LNURL guards: 6/6 pre-spawn, 1/1 inprocess before service; writer ordering 3/3",flush=True)


def path_stress(environment):
    package = ROOT/"packages/lightning"
    with chdir(package):
        built = network.run_owned(["lake","build","LightningTests"],env=environment,
            capture_output=True,timeout=120)
    assert built.returncode==0, "LNURL large callback build: "+built.stderr.decode()
    try:
        with chdir(package):
            stress = network.run_owned([str(package/".lake/build/bin/LightningTests"),
                "--lnurl-case","large-path"], env=environment,
                capture_output=True,timeout=10)
    except subprocess.TimeoutExpired:
        raise AssertionError("LNURL large callback normalization exceeds 10s budget") from None
    assert stress.returncode==0 and b"large callback paths: 2/2" in stress.stdout, "LNURL large callback normalization results"
    print("LNURL large callback normalization: 2/2 within 10s test budget",flush=True)


def parser(root,env):
    # Help and consumed option values are parsed before any network is possible.
    rows = [(["--help"],0), ([ADDRESS,"bad","--help"],0), (["-c","--help"],1),
            (["-c=--help","--help"],0), (["-cfoo=bar","--help"],0),
            (["--comment=","--help"],0), (["-c","","--help"],0),
            (["-o","--help"],1), (["--help","--invalid"],0),
            (["--invalid","--help"],1), ([ADDRESS],1)]
    for args,status in rows:
        proc = subprocess.run([str(EXE),"ln-generate-invoice",*args],cwd=root/"home",env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
        assert proc.returncode==status and bool(proc.stdout)==(status==0) and bool(proc.stderr)==(status!=0), "LNURL parser/help "+repr(args)
    print("LNURL parser/help ordering: 11/11",flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--path-stress"]: path_stress(dict(os.environ))
    elif sys.argv[1:2]==["--isolated"]: replay(sys.argv[2] if len(sys.argv)>2 else None)
    else:
        assert not sys.argv[1:] or (len(sys.argv)==3 and sys.argv[1]=="--probe")
        sys.exit(network.run_isolated([sys.executable,"-B",str(Path(__file__).resolve()),"--isolated",*sys.argv[2:]],timeout=240))
