#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Synthetic guardian replay, exact independent captures and bounded controls."""
from contextlib import contextmanager, chdir
from copy import deepcopy
import base64
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
import threading
import time
from unittest.mock import patch
from urllib.parse import urljoin

from cases import APP, ROOT, PIN
from compare import exact_json
from evidence import write_record
import network

PORT = 19444
BASE = "http://127.0.0.1:" + str(PORT)
EXE = APP / ".lake/build/bin/cyberkrill"
TEST = APP / ".lake/build/bin/CyberkrillTests"
FIXTURE = APP / "test/http/fetch-config.json"
REFERENCE = APP / "test/http/fetch-config-reference.json"
PROVENANCE = APP / "test/http/fetch-config.provenance.json"


def invoke(exe, args, root, payload=None, timeout=15):
    with chdir(root):
        # Input-bearing test entries need a pipe; the owned wrapper itself is
        # still foreground and reaps its whole process tree on cancellation.
        command = [sys.executable, "-B", "-c",
                   'import subprocess,sys; p=subprocess.run(sys.argv[2:],input=open(sys.argv[1],"rb").read(),capture_output=True); sys.stdout.buffer.write(p.stdout); sys.stderr.buffer.write(p.stderr); sys.exit(p.returncode)',
                   str(root/"stdin"), str(exe), *args]
        (root/"stdin").write_bytes(payload or b"")
        return network.run_owned(command, timeout=timeout, capture_output=True,
            env=dict(os.environ, HOME=str(root/"home"), TMPDIR=str(root), PYTHONDONTWRITEBYTECODE="1"))


def generate():
    """Construct test invites with the existing encoder, never a live invite."""
    primary_rows = json.loads((ROOT/"packages/fedimint-invite/test-data/primary.json").read_bytes())
    primary = primary_rows[0]["decoded"]
    identity = primary["federation_id"]
    full = {"federation_id":identity, "global":{
        "api_endpoints":{"10":"opaque endpoint ten", "2":"wss://synthetic.invalid/two", "0":""},
        "meta":{"federation_name":"Synthetic Federation", "guardian_0_name":"Zero", "guardian_2_name":"Two",
                "note":"authored fixture", "ignored":False}, "consensus_version":"2.1"},
        "modules":{"0":{"kind":"mint","amount":123}, "nested":[True,None,"fixture"]}}
    defaults = {"federation_id":identity, "global":{"api_endpoints":{}}}
    peers = deepcopy(defaults)
    peers["global"]["api_endpoints"] = {"1":"one", "01":"zero-one", "+1":"plus-one", "000":"zero", "+0":"plus-zero", "65535":"last"}
    targets = {"single":[BASE.replace("http:","ws:")+"/first"],
               "two":[BASE.replace("http:","ws:")+"/first", BASE.replace("http:","ws:")+"/second"],
               "slash":[BASE.replace("http:","ws:")+"/first/"],
               "double":[BASE.replace("http:","ws:")+"/first//"],
               "many":[BASE.replace("http:","ws:")+"/first///////"],
               "normalize":["HTTP://127.0.0.1:019444/a/../first"],
               "query":[BASE.replace("http:","ws:")+"/first?note='raw'"],
               "wss":[BASE.replace("http:","wss:")+"/first"],
               "embedded":[BASE.replace("http:","ws:")+"/wss://inside/ws://tail//"],
               "unsafe":["ws://external.invalid/first"],
               "unsupported":["ws://[::1]/first"],
               "8332":["ws://127.0.0.1:8332/first"]}
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary); (root/"home").mkdir()
        invites={}
        for name, urls in targets.items():
            value=deepcopy(primary_rows[1 if name=="two" else 0]["decoded"])
            assert len(value["guardians"])==len(urls), "reviewed guardian count " + name
            for guardian,url in zip(value["guardians"],urls):
                guardian["url"]=url
            p=invoke(EXE,["fm-encode-invite","-"],root,json.dumps(value).encode())
            assert p.returncode==0 and not p.stderr, "synthetic invite encoder " + name
            invites[name]=p.stdout.decode().strip()
    builder=importlib.import_module("offline-inputs").INV
    # Failed consensus; six-byte https marker, printable URL then a delimiter.
    invites["fallback"]=builder.wrap(b"\xff\0\0\0"+(BASE.replace("http:","https:")+"/first").encode()+b"\0"+bytes.fromhex(identity))
    value=dict(port=PORT,identity=identity,two_identity=primary_rows[1]["decoded"]["federation_id"],
               invites=invites,full=full,defaults=defaults,peers=peers)
    write_record(FIXTURE,json.dumps(value,indent=2)+"\n")
    provenance=dict(origin="Synthetic guardian replies and invites; authored from the pinned config projection. Consensus invites preserve the reviewed Phase 6 one- or two-guardian vector except for URLs; the fallback payload is synthetic and keeps the one-guardian vector ID. No original endpoint is contacted.",
        source="https://github.com/douglaz/cyberkrill",revision=PIN,paths=["fedimint-lite/src/lib.rs:435-630,659-737","cyberkrill/src/main.rs:596-602,1968-1976"],licence="MIT OR Apache-2.0, taken under MIT",
        fixture_sha256=hashlib.sha256(FIXTURE.read_bytes()).hexdigest())
    write_record(PROVENANCE,json.dumps(provenance,indent=2)+"\n")


def fixtures():
    value=json.loads(FIXTURE.read_bytes()); provenance=json.loads(PROVENANCE.read_bytes())
    assert provenance["revision"]==PIN and value["port"]==PORT
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest()==provenance["fixture_sha256"], "config fixed fixture provenance"
    assert len(value["invites"])==13, "config synthetic invite inventory"
    return value


def cases():
    f=fixtures(); full=json.dumps(f["full"],separators=(",",":")); good=dict(body=full)
    def step(method="GET", path="/first/config", **response):
        return dict(method=method,path=path,body="{}" if method=="POST" else "",response=response or deepcopy(good))
    def row(name, steps=None, **kwargs):
        return dict(name=name,steps=[step()] if steps is None else steps,expected="full",**kwargs)
    rows=[row("get"),row("get-status-post",[step(status=503),step("POST")]),
          row("get-transport-post",[step(error="disconnect"),step("POST")]),
          row("post-transport-next",[step(status=500),step("POST",error="disconnect"),step(path="/second/config")],invite="two"),
          row("post-status-next",[step(status=500),step("POST",status=404),step(path="/second/config")],invite="two"),
          row("post-json-next",[step(status=500),step("POST",body="not JSON"),step(path="/second/config")],invite="two"),
          row("all-fail",[step(status=503),step("POST",status=500),step(path="/second/config",status=404),step("POST",path="/second/config",status=403)],invite="two",error="fmAllGuardiansFailed"),
          row("non-json-next",[step(body="not JSON"),step(path="/second/config")],invite="two"),
          row("utf8-next",[step(bytes=list((full[:-1]+',"ignored":"').encode()+b'\xff"}')),step(path="/second/config")],invite="two"),
          row("first-success",invite="two")]
    for name,key in [("slash","slash"),("double-slash","double"),("many-slashes","many"),("normalize","normalize")]:
        rows.append(row(name,invite=key))
    rows.append(row("query",[step(path="/first?note=%27raw%27/config")],invite="query",injected=True,capture=True))
    hard=[("missing-endpoints",{},"fmMissingApiEndpoints"),
          ("id-mismatch",dict(f["defaults"],federation_id="synthetic mismatch"),"fmFederationIdMismatch"),
          ("id-type",dict(f["defaults"],federation_id=3),"fmFederationIdType")]
    for name, endpoints, error in [("array",[],"fmInvalidApiEndpoints"),("null",None,"fmInvalidApiEndpoints"),
        ("bad-peer",{"nope":"opaque"},"fmInvalidPeerId"),("peer-overflow",{"65536":"opaque"},"fmInvalidPeerId"),
        ("peer-underscore",{"1_0":"opaque"},"fmInvalidPeerId"),("peer-negative",{"-0":"opaque"},"fmInvalidPeerId"),
        ("endpoint-type",{"0":{}},"fmEndpointType")]:
        body=deepcopy(f["defaults"]); body["global"]["api_endpoints"]=endpoints
        hard.append((name,body,error))
    for name, body, error in hard:
        rows.append(row(name,[step(body=json.dumps(body))],invite="two",error=error))
    for name in ["defaults","peers"]:
        r=row(name,[step(body=json.dumps(f[name]))]); r["expected"]=name; rows.append(r)
    absent=deepcopy(f["full"]); del absent["federation_id"]
    rows.append(row("absent-id",[step(body=json.dumps(absent))],warning=True))
    optionals=deepcopy(f["defaults"]); optionals["global"].update(meta=[],consensus_version=12)
    r=row("optional-types",[step(body=json.dumps(optionals))]);r["expected"]="defaults";rows.append(r)
    for status in [301,302,303,307,308]:
        rows.append(row("get-redirect-"+str(status),[step(status=status,headers={"Location":"./done?note='raw'"}),step(path="/first/done?note='raw'")]))
        method="POST" if status in [307,308] else "GET"
        rows.append(row("post-redirect-"+str(status),[step(status=500),step("POST",status=status,headers={"Location":"/done"}),step(method,path="/done")]))
    for name, headers in [("missing",{}),("invalid",{"Location":"/bad[x]"})]:
        rows.append(row("redirect-"+name,[step(status=302,headers=headers),step("POST")]))
    rows.append(row("redirect-ten",[step(path="/first/config" if i==0 else "/hop"+str(i),status=302,headers={"Location":"/hop"+str(i+1)}) for i in range(10)]+[step(path="/hop10")]))
    rows.append(row("redirect-limit",[step(status=302,headers={"Location":"/first/config"}) for _ in range(11)]+[step("POST")]))
    # Bound controls all carry a following valid guardian. Numeric refusals occur
    # after GET success and must neither POST nor reach semantic validation.
    tokens={}
    for n in [2047,2048,2049]: tokens["token-"+str(n)]="0e"+"0"*(n-2)
    for n in [1023,1024,1025]:
        tokens["coefficient-"+str(n)]="0."+"0"*(n-2)+"1"
        tokens["exponent-"+str(n)]="0e"+str(n)
        tokens["negative-exponent-"+str(n)]="1e-"+str(n)
    for name, token in tokens.items():
        body=full[:-1]+',"ignored":'+token+'}'
        refused=name.endswith(("2049","1025"))
        rows.append(row(name,[step(body=body)]+([step(path="/second/config")] if refused else []),invite="two"))
    for kind,opening,closing in [("array","[","]"),("object",'{"x":',"}")]:
        for depth in [126,127,128]:
            body=full[:-1]+',"ignored":'+opening*(depth-1)+"0"+closing*(depth-1)+'}'
            rows.append(row(kind+"-depth-"+str(depth),[step(body=body)]+([step(path="/second/config")] if depth>=128 else []),invite="two"))
    quoted=deepcopy(f["full"]);quoted["ignored"]='[{\\"1e99999999999' * 150
    rows.append(row("quoted",[step(body=json.dumps(quoted))]))
    for name, raw in [("surrogate",'"\\uD800"'),("numeric-key",'{1:2}'),("invalid-number","01")]:
        rows.append(row(name,[step(body=full[:-1]+',"ignored":'+raw+'}'),step(path="/second/config")],invite="two"))
    for size in [1048575,1048576,1048577]:
        body=full+" "*(size-len(full.encode()))
        rows.append(row("bytes-"+str(size),[step(body=body)]+([step("POST")] if size>1048576 else [])))
    # Real delayed response controls measure total and TLS-handshake connect time.
    for ms in [1900,2000,2100]:
        rows.append(row("total-"+str(ms),[step(body=full,delay_ms=ms)]+([step("POST")] if ms>=2000 else []),timing=True))
    for name in ["file","retained-handle","write-failure","decode-file-failure","open-failure"]:
        rows.append(row(name,file=name,**({"error":"outputFailure:"} if name in ["write-failure","open-failure"] else {"error":"invalidInvite"} if name=="decode-file-failure" else {})))
    # Injection checks exact headers/settings and refused targets without sockets.
    for name, key, url in [("wss","wss",BASE.replace("http:","https:")+"/first/config"),
        ("embedded","embedded",BASE+"/https://inside/http://tail/config"),
        ("fallback","fallback",BASE.replace("http:","https:")+"/first/config")]:
        rows.append(row(name,injected=True,invite=key,urls=[url]))
    for name,key in [("unsafe","unsafe"),("unsupported","unsupported")]:
        rows.append(row(name,[] if name=="unsupported" else [step(error="disconnect"),step("POST",error="disconnect")],injected=True,invite=key,
                        error="fmAllGuardiansFailed"))
    for name in ["token-2049","coefficient-1025","exponent-1025","array-depth-128","bytes-1048577","utf8-next","post-json-next",
                 "double-slash","get-redirect-302","post-redirect-302","redirect-ten"]:
        item=deepcopy(next(r for r in rows if r["name"]==name));item.update(name="injected-"+name,injected=True);rows.append(item)
    for size in [8191,8192,8193]:
        target=BASE+"/"+"x"*(size-len(BASE)-1)
        steps=[step(status=302,headers={"Location":target})]
        steps.append(step("POST") if size>8192 else step(path="/"+"x"*(size-len(BASE)-1)))
        rows.append(row("url-"+str(size),steps,injected=True))
    # A redirect that resolves over the URL bound has a short Location itself.
    rows.append(row("resolved-url-limit",[step(status=302,headers={"Location":BASE+"/"+"x"*8150+"/file"}),
        step(path="/"+"x"*8150+"/file",status=302,headers={"Location":"y"*100}),step("POST")],injected=True))
    rows.append(row("location-limit",[step(status=302,headers={"Location":"/"+"x/../"*1638+"aa"}),step("POST")],injected=True))
    for name in ["bytes-1048575","bytes-1048576"]:
        item=deepcopy(next(r for r in rows if r["name"]==name));item.update(name="injected-"+name,injected=True);rows.append(item)
    for name,key,error in [("initial-unsafe","unsafe","testConfigRefused"),("initial-8332","8332","testArgRefused")]:
        rows.append(row(name,[],invite=key,injected=True,guarded=True,error=error))
    for status in [301,302,303,307,308]:
        rows.append(row("unsafe-redirect-"+str(status),[
            step(status=status,headers={"Location":"http://external.invalid/refused"}),
            step("POST",status=status,headers={"Location":"http://external.invalid/refused"})],injected=True,guarded=True,error="fmAllGuardiansFailed"))
    for bound,name in [("fmJsonTokenLimit","token-2049"),("fmJsonCoefficientLimit","coefficient-1025"),
        ("fmJsonExponentLimit","exponent-1025"),("fmJsonDepthLimit","array-depth-128"),
        ("fmUtf8Decode","utf8-next")]:
        source=next(r for r in rows if r["name"]==name)
        rows.append(row("diagnostic-"+name,[deepcopy(source["steps"][0])],injected=True,error=bound))
    rows.append(row("post-utf8-next",[step(status=503),step("POST",bytes=[255]),step(path="/second/config")],invite="two"))
    rows.append(row("post-preflight-next",[step(status=503),step("POST",body=full[:-1]+',"modules":0e1025}'),step(path="/second/config")],invite="two"))
    rows.append(row("empty-modules",[step(body=json.dumps(dict(f["defaults"],modules=None)))],expected_override=dict()))
    # Distinct exact integer, within both implementations' integer range.
    numeric=deepcopy(f["full"]);numeric["modules"]={"n":9007199254740993}
    rows.append(row("exact-modules",[step(body=json.dumps(numeric))],expected_override={"modules":{"n":9007199254740993}}))
    for name,token,refusal in [("finite-below","1.7976931348623157e308",False),
        ("finite-midpoint",str(2**1024-2**970),True),("finite-above",str(2**1024-2**970+1),True),
        ("ignored-overflow","1e309",True),("ignored-negative-overflow","-1e309",True)]:
        rows.append(row(name,[step(body=full[:-1]+',"ignored":'+token+'}')]+([step(path="/second/config")] if refusal else []),invite="two"))
    for name,body in [("root-overflow","1e400"),("modules-overflow",full[:-1]+',"modules":1e400}')]:
        rows.append(row(name,[step(body=body),step(path="/second/config")],invite="two"))
    source=next(r for r in rows if r["name"]=="ignored-overflow")
    rows.append(row("diagnostic-number-range",[deepcopy(source["steps"][0])],injected=True,error="fmJsonNumberRange"))
    for name,token in [("modules-fraction","1.0000000000000001"),("modules-integer","18446744073709551617")]:
        rows.append(row(name,[step(body=full[:-1]+',"modules":'+token+'}')],module_number=token))
    for name,key,target in [("https-downgrade","wss",BASE+"/done"),
        ("https-upgrade","single",BASE.replace("http:","https:")+"/done")]:
        rows.append(row(name,[step(status=302,headers={"Location":target}),step(path="/done")],
                        invite=key,injected=True,urls=[(BASE.replace("http:","https:") if key=="wss" else BASE)+"/first/config",target]))
    assert len(rows)==127, "config replay inventory"
    # The reviewed two-guardian vector retains its own ID and optional secret.
    # Bind authored replies to that ID without changing their field shapes.
    for row in rows:
        if row.get("invite")=="two":
            for step in row["steps"]:
                response=step["response"]
                if "body" in response:
                    assert response["body"].count(f["identity"])<=1, "single response ID binding"
                    response["body"]=response["body"].replace(f["identity"],f["two_identity"])
                if "bytes" in response:
                    body=bytes(response["bytes"])
                    assert body.count(f["identity"].encode())<=1, "single byte response ID binding"
                    response["bytes"]=list(body.replace(f["identity"].encode(),f["two_identity"].encode()))
    return rows



def short_cases():
    f = fixtures()
    good = deepcopy(f["full"]); good["federation_id"] = f["two_identity"]
    post = deepcopy(good); post["modules"] = {"chosen":"same guardian POST"}
    following = deepcopy(good); following["modules"] = {"chosen":"next guardian GET"}
    def step(method="GET", path="/first/config", **response):
        return dict(method=method, path=path, body="{}" if method=="POST" else "", response=response)
    rows = []
    for name, raw, status in [("short-length-200","length",200), ("short-chunked-200","chunked",200),
                              ("short-500","length",500), ("before-headers","disconnect",200),
                              ("post-body-failure","post",200)]:
        first = step(status=500) if raw=="post" else step(status=status, raw=raw)
        steps = [first]
        if name in ["short-500","before-headers"]:
            steps.append(step("POST", body=json.dumps(post)))
            chosen = "same guardian POST"
        else:
            if raw=="post": steps.append(step("POST", status=200, raw="length"))
            steps.append(step(path="/second/config", body=json.dumps(following)))
            chosen = "next guardian GET"
        rows.append(dict(name=name, steps=steps, invite="two", expected="full", chosen=chosen,
                         alternate=step("POST", body=json.dumps(post))))
    assert len(rows)==5, "config short-body inventory"
    return rows


def ready_config(fixture, row):
    value=deepcopy(fixture["full"])
    if row.get("invite")=="two":value["federation_id"]=fixture["two_identity"]
    return value


def reference_cases():
    rows=[r for r in cases() if (not r.get("injected") or r.get("capture")) and not r.get("file") and not r.get("timing") and not r["name"].startswith("bytes-")]
    assert len(rows)==78,"reference config inventory"
    return rows


@contextmanager
def responder(root, steps, collision=False, ready=None):
    entries=[]
    for step in steps:
        entry=next((e for e in entries if (e["method"],e["path"])==(step["method"],step["path"])),None)
        if entry is None:
            entry=dict(method=step["method"],path=step["path"],body={"text":step["body"]},responses=[]);entries.append(entry)
        response=deepcopy(step["response"])
        if "body" in response: response["text"]=response.pop("body")
        entry["responses"].append(response)
    if ready is not None and not any(e["method"]=="GET" and e["path"]=="/second/config" for e in entries):
        entries.append(dict(method="GET",path="/second/config",responses=[dict(json=ready)]))
    spec=root/"responses.json";spec.write_text(json.dumps(dict(entries=entries)))
    log=root/"requests.jsonl";log.write_bytes(b"")
    program='''import importlib.util,sys,time
spec=importlib.util.spec_from_file_location("responder",sys.argv.pop(1)); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original=m.Handler.send_recorded
def send(self,response):
 time.sleep(float(response.get("delay_ms",0))/1000)
 if "error" in response:
  self.close_connection=True;return
 if "raw" in response:
  raw=response["raw"]; self.close_connection=True
  if raw=="disconnect":return
  status=int(response.get("status",200))
  if raw=="interim":self.wfile.write(b"HTTP/1.1 100 Continue\\r\\n\\r\\n");return
  if raw=="header":self.wfile.write(b"HTTP/1.1 200 OK\\r\\nContent-Len");return
  if raw=="invalid-header":self.wfile.write(b"HTTP/1.1 200 OK\\r\\nContent-Length: 1000\\r\\nX-Test: \\xff\\r\\n\\r\\n{");return
  self.protocol_version="HTTP/1.1";self.send_response(status)
  if raw=="length":self.send_header("Content-Length","1000")
  else:self.send_header("Transfer-Encoding","chunked")
  self.end_headers();self.wfile.write(b"{" if raw=="length" else b"1\\r\\n{\\r\\n");self.wfile.flush();return
 if "bytes" in response:
  body=bytes(map(int,response["bytes"]));self.send_response(int(response.get("status",200)));self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body);return
 original(self,response)
m.Handler.send_recorded=send;m.main()
'''
    with (root/"responder.stderr").open("wb") as errors:
        child=subprocess.Popen([sys.executable,"-B","-c",program,str(ROOT/"packages/http-curl/test/responder.py"),str(spec),"--port",str(PORT),"--log",str(log)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,cwd=root,
            env=dict(os.environ,TMPDIR=str(root),HOME=str(root/"home"),PYTHONDONTWRITEBYTECODE="1"))
        handlers={}
        try:
            for sig in [signal.SIGHUP,signal.SIGINT,signal.SIGQUIT,signal.SIGTERM]:
                handlers[sig]=signal.signal(sig,lambda signum,_:sys.exit(128+signum))
            assert select.select([child.stdout],[],[],10)[0], "config responder startup"
            ready=child.stdout.readline().decode().split()
            if collision: assert not ready and child.wait(timeout=5)!=0, "config collision refused before READY"
            else: assert len(ready)==3 and ready[0]=="READY" and int(ready[1])==PORT and child.poll() is None, "config fixed-port READY"
            yield log
        finally:
            for sig in handlers: signal.signal(sig,signal.SIG_IGN)
            try:
                child.stdin.close();child.wait(timeout=6);child.stdout.close()
                assert child.returncode==(1 if collision else 0), "config responder reaped"
            finally:
                for sig,handler in handlers.items():signal.signal(sig,handler)
    if not collision: assert not (root/"responder.stderr").read_bytes(), "config responder unmatched/exhausted reply"


def expected_trace(steps):
    return [dict(method=s["method"],path=s["path"],body=s["body"]) for s in steps]


def replay(only=None):
    assert network.sandbox() or network.isolated(), "config replay isolation"
    f=fixtures(); captures=json.loads(REFERENCE.read_bytes())
    assert hashlib.sha256(REFERENCE.read_bytes()).hexdigest()==json.loads(PROVENANCE.read_bytes())["capture_sha256"],"config independently pinned capture"
    assert captures["revision"]==PIN and len(captures["captures"])==78,"config reference pin and inventory"
    assert captures["fixture_sha256"]==hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),"config captured fixture binding"
    assert captures["script_sha256"]==hashlib.sha256((APP/"test/capture-fetch-config.py").read_bytes()).hexdigest(),"config captured script binding"
    assert captures["cases_sha256"]==hashlib.sha256(json.dumps(reference_cases(),sort_keys=True).encode()).hexdigest(),"config captured definitions binding"
    observations={r["name"]:r for r in captures["captures"]}
    values={r["name"]:exact_json(r["stdout"]) for r in captures["captures"] if r["name"] in ["get","defaults","peers"]}
    assert len(values)==3, "config independent success values"
    values["full"]=values["get"]
    rows=cases()+short_cases()
    short = json.loads((APP/"test/http/fetch-config-short-reference.json").read_bytes())
    provenance = json.loads((APP/"test/http/fetch-config-short.provenance.json").read_bytes())
    assert provenance["capture_sha256"]==hashlib.sha256((APP/"test/http/fetch-config-short-reference.json").read_bytes()).hexdigest(), "config short-body provenance"
    assert short["revision"]==PIN and len(short["captures"])==5, "config short-body reference inventory"
    assert short["cases_sha256"]==hashlib.sha256(json.dumps(short_cases(),sort_keys=True).encode()).hexdigest(), "config short-body captured definitions"
    assert short["script_sha256"]==hashlib.sha256((APP/"test/capture-fetch-config-short.py").read_bytes()).hexdigest(), "config short-body captured script"
    observations.update({r["name"]:r for r in short["captures"]})
    if only: rows=[r for r in rows if r["name"]==only];assert len(rows)==1, "config probe selection"
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary);(root/"home").mkdir()
        for row in rows:
            name=row["name"]; steps=row["steps"];args=["fm-fetch-config",f["invites"][row.get("invite","single")]]
            target=root/"output";target.unlink(missing_ok=True);(root/"output.opened").unlink(missing_ok=True)
            if row.get("file"):
                if name=="open-failure": target=root/"missing"/"out"
                elif name=="write-failure": target=Path("/dev/full")
                else: target.write_text("previous")
                args += ["-o",str(target)]
                if name in ["decode-file-failure","open-failure"]:args[1]="malformed";steps=[]
            injected=row.get("injected",False)
            replies=[]
            for step in steps:
                response=deepcopy(step["response"])
                response["headers"]=[(k.lower(),v) for k,v in response.get("headers",{}).items()]
                replies.append(response)
            payload=json.dumps([dict(args=args,injected=injected,replies=replies,replace=name=="retained-handle")]).encode()
            if row.get("guarded"):
                payload=json.dumps([dict(args=args,injected=True,replies=replies,guarded=True)]).encode()
            started=time.monotonic()
            if injected:
                p=invoke(TEST,["--fetch-config-run"],root,payload)
                log_values=None
            else:
                network.refuse_spawn(args,BASE)
                with responder(root,steps+([row["alternate"]] if row.get("alternate") and not any(s["method"]=="POST" for s in steps) else []),ready=ready_config(f,row) if row.get("invite")=="two" else None) as log:
                    p=invoke(TEST,["--fetch-config-run"],root,payload)
                    log_values=[json.loads(line) for line in log.read_text().splitlines()]
            assert p.returncode==0, "config test entry "+name+": "+p.stderr.decode()
            result=json.loads(p.stdout)[0]
            if name=="bytes-1048577":
                assert result["calls"] and result["calls"][0]["transport"]=="tooLarge", "config transport body bound"
            label="config refusal " if row.get("error") else "config success "
            assertion=label+name
            if row.get("error"):
                assert result["status"]==1 and result["stdout"]=="" and row["error"] in result["stderr"], assertion
            else:
                text=result["stdout"]
                if row.get("file"):text=(root/"output.opened" if name=="retained-handle" else target).read_text()
                expected=deepcopy(values[row["expected"]])
                if row.get("invite")=="two":expected["federation_id"]=f["two_identity"]
                if name=="empty-modules":expected=deepcopy(values["defaults"]);expected["modules"]=None
                if name=="exact-modules":expected["modules"]={"n":exact_json("9007199254740993")}
                if "module_number" in row:expected["modules"]=exact_json(row["module_number"])
                if "chosen" in row:expected["modules"]={"chosen":row["chosen"]}
                assert result["status"]==0 and text and exact_json(text)==expected and not text.endswith("\n"), assertion+": "+repr(result)
                if name in observations and observations[name]["status"]==0:
                    if name in ["modules-fraction","modules-integer"]:
                        ref_expected=deepcopy(values["full"])
                        ref_expected["modules"]=exact_json("1.0" if name=="modules-fraction" else "18446744073709552000")
                        assert exact_json(observations[name]["stdout"])==ref_expected,assertion+" pinned numeric rounding"
                    elif name=="post-preflight-next":
                        # Named bounded-number delta: serde accepts 0e1025 in
                        # modules; preflight refuses it and tries guardian two.
                        ref_expected=deepcopy(values["full"])
                        if row.get("invite")=="two":ref_expected["federation_id"]=f["two_identity"]
                        ref_expected["modules"]=exact_json("0")
                        assert exact_json(observations[name]["stdout"])==ref_expected and observations[name]["requests"]==expected_trace(steps[:2]),assertion+" bounded numeric reference"
                    else:
                        assert exact_json(text)==exact_json(observations[name]["stdout"]),assertion+" independent reference JSON"
                assert bool(result["stderr"])==bool(row.get("warning")), assertion+" stderr"
                if row.get("warning"):assert "Could not verify federation ID" in result["stderr"], assertion
            if row.get("file") and name not in ["open-failure","write-failure"]:
                assert result["stdout"]=="", assertion+" file stdout"
                if row.get("error"):assert target.read_bytes()==b"",assertion+" truncated"
                if name=="retained-handle":assert target.read_text()=="replacement leaf",assertion+" original handle"
            if log_values is not None:assert log_values==expected_trace(steps), assertion+" raw request trace"
            if "chosen" in row:
                assert observations[name]["requests"]==expected_trace(steps), assertion+" independent reference trace"
            calls=result["calls"]
            assert len(calls)==len(steps), assertion+" request count"
            for i,(call,step) in enumerate(zip(calls,steps)):
                url=row.get("urls",[])[i] if row.get("urls") else BASE+step["path"]
                if row.get("invite")=="unsafe":url="http://external.invalid/first/config"
                assert (call["method"],call["url"],call["body"])==(step["method"],url,step["body"]),assertion+" injected trace"
                headers=[["Content-Type","application/json"]] if step["method"]=="POST" else []
                if i:
                    previous=steps[i-1];status=previous["response"].get("status",200)
                    location=previous["response"].get("headers",{}).get("Location")
                    method="GET" if status in [301,302,303] else previous["method"]
                    prior=calls[i-1]["url"]
                    if location is not None and status in [301,302,303,307,308] and method==step["method"] and urljoin(prior,location)==url:
                        if not (prior.startswith("https://") and url.startswith("http://")):
                            headers.append(["Referer",prior.replace("'","%27")])
                assert call["headers"]==headers,assertion+" request headers"
                assert (call["bytes"],call["connect"],call["total"])==(1048576,1000,2000),assertion+" transport settings"
            if row.get("timing"):assert time.monotonic()-started<5,assertion+" finite timeout"
            print(assertion,flush=True)
        if not only:
            with responder(root,[dict(method="GET",path="/unused",body="",response={})]):
                with tempfile.TemporaryDirectory(dir=root) as second:
                    second=Path(second);(second/"home").mkdir()
                    with responder(second,[],collision=True):pass
    print(f"config replay: {len(rows)}/"+str(len(rows))+"; synthetic invites: 13/13; independent captures: 83/83; base success values: 3/3",flush=True)


def parser_and_guards():
    f=fixtures()
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary);(root/"home").mkdir()
        for i,args in enumerate([["fm-fetch-config"],["fm-fetch-config","bad","extra"],
            ["fm-fetch-config","bad","--unknown"],["fm-fetch-config","bad","-o"],
            ["fm-fetch-config","bad","-o","x","-o","y"],["fm-fetch-config","bad","--help=x"],
            ["fm-fetch-config","--unknown","--help"],["fm-fetch-config","--help","--unknown"],
            ["fm-fetch-config","-hx"],["fm-fetch-config","bad"],["fm-fetch-config","--","bad"]]):
            p=invoke(EXE,args,root)
            help_case=i in [7,8]
            assert (p.returncode==0 and b"fm-fetch-config" in p.stdout and not p.stderr) if help_case else (p.returncode==1 and not p.stdout and p.stderr), "config parser "+str(i)
        p=invoke(TEST,["--fetch-config-ordering"],root)
        assert p.returncode==0 and b"config injected ordering: 2/2" in p.stdout,"config output ordering"
        # Spy on child creation: refusals must happen before subprocess.run.
        for key in ["8332","unsafe","unsupported"]:
            with patch.object(network.subprocess,"run",side_effect=AssertionError("config child started before guard")):
                try:network.checked_run(EXE,["fm-fetch-config",f["invites"][key]],stub_url=BASE)
                except ValueError:pass
                else:raise AssertionError("config unsafe spawn accepted")
        steps=[dict(method="GET",path="/first/config",body="",response=dict(body=json.dumps(f["full"])))]
        # Release dispatch has no test overrides. Only this fixed local initial
        # destination and a nonredirecting reply are admitted before spawning.
        args=["fm-fetch-config",f["invites"]["single"]]
        network.refuse_spawn(args,BASE)
        with responder(root,steps) as log:
            p=invoke(EXE,args,root)
            assert p.returncode==0 and exact_json(p.stdout)==exact_json(next(r for r in json.loads(REFERENCE.read_bytes())["captures"] if r["name"]=="get")["stdout"]) and not p.stderr,"config release dispatch"
            assert [json.loads(line) for line in log.read_text().splitlines()]==expected_trace(steps),"config release exact trace"
    print("config parser: 11/11; ordering: 2/2; no-child refusals: 3/3; release dispatch: 1/1",flush=True)



def guardian_guards(only=None):
    f = fixtures(); builder = importlib.import_module("offline-inputs").INV
    primary = json.loads((ROOT/"packages/fedimint-invite/test-data/primary.json").read_bytes())
    def synthetic(urls):
        value = deepcopy(primary[1 if len(urls)==2 else 0]["decoded"])
        assert len(value["guardians"])==len(urls), "config reviewed guard invite shape"
        for guardian, url in zip(value["guardians"], urls): guardian["url"] = url
        return builder.wrap(builder.consensus(value))
    controls = []
    for spelling in ["HTTP://external.invalid:19444/first", "http:external.invalid:19444/first"]:
        for later in [False, True]:
            urls = (["ws://127.0.0.1:19444/first"] if later else []) + [spelling]
            invite = synthetic(urls)
            controls.append(("guard-"+("upper" if spelling.startswith("HTTP") else "slashless")+("-later" if later else "-first"), invite))
    if only:
        controls = [r for r in controls if r[0]==only]
        assert len(controls)==1, "config guard selection"
    for name, invite in controls:
        with patch.object(network.subprocess,"run") as child:
            try: network.checked_run(EXE,["fm-fetch-config",invite],stub_url=BASE)
            except ValueError: pass
            assert not child.called, "config no child " + name
    if not only:
        for key, count in [("single",1),("two",2),("normalize",1),("fallback",1)]:
            assert len(network.effective_guardians(f["invites"][key]))==count, "config guardian decode " + key
            network.refuse_spawn(["fm-fetch-config",f["invites"][key]], BASE)
        for target in ["HTTP://127.0.0.1:019444/a/../first", "http:127.0.0.1:19444/first", "http://%31%32%37.0.0.1:19444/first"]:
            invite = synthetic([target])
            with patch.object(network.subprocess,"run") as child:
                network.checked_run(EXE,["fm-fetch-config","-o","unused",invite],stub_url=BASE)
                assert child.call_count==1, "config normalized loopback spawn"
        assert network.effective_guardians("malformed")==[], "config malformed guardian wrapper"
        print("config guardian guards: 4/4 no-child refusals; 4/4 strict/fallback decodes; 3/3 normalized loopback controls; malformed: 1/1",flush=True)


def http_capabilities():
    """Actual framing failures through both additive and legacy operations."""
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary); (root/"home").mkdir()
        for raw,status in [("length",200),("chunked",200),("length",500),("disconnect",200),("interim",100),("header",200),("invalid-header",200)]:
            step=dict(method="GET",path="/probe",body="",response=dict(raw=raw,status=status))
            with responder(root,[step,step]) as log:
                payload=json.dumps(dict(url=BASE+"/probe")).encode()
                p=invoke(TEST,["--fetch-http-run"],root,payload)
                assert p.returncode==0, "config HTTP capability entry"
                result=json.loads(p.stdout)
                acquired=raw in ["length","chunked"]
                assert result["legacy"]==("ok" if raw=="header" else "error"), "config legacy framing result " + raw
                assert result["detailed"]==("body" if acquired else "error"), "config acquired body boundary " + raw
                if acquired: assert result["status"]==status, "config acquired status"
                if raw=="invalid-header":
                    assert result["legacy_code"]==18 and result["detailed_code"]==8, "config legacy transfer error before header decode"
                assert [json.loads(line) for line in log.read_text().splitlines()]==expected_trace([step,step]), "config HTTP capability trace"
        print("config HTTP capabilities: 7/7 legacy framing results; 7/7 detailed final/body-stage controls",flush=True)


def connect_deadlines():
    """Held local sockets never complete TLS; trust setup is owned by the test."""
    f=fixtures()
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary);(root/"home").mkdir()
        # libcurl requires a readable CA bundle before opening HTTPS sockets.
        # Own it here so a sandbox without host certificates tests the deadline.
        certificate=root/"held-socket-ca.crt"
        generated=network.run_owned(["openssl","req","-x509","-newkey","ec",
            "-pkeyopt","ec_paramgen_curve:P-256","-nodes","-days","1",
            "-subj","/CN=localhost","-keyout",str(root/"held-socket.key"),
            "-out",str(certificate)],capture_output=True,timeout=15,
            env=dict(os.environ,HOME=str(root/"home"),TMPDIR=str(root)))
        assert generated.returncode==0 and certificate.is_file(),"config held socket trust setup"
        for delay in [900,1000,1100]:
            listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(("127.0.0.1",PORT));listener.listen();listener.settimeout(5)
            stop=threading.Event();accepted=[]
            def hold():
                try:
                    # Two handshake attempts, GET and fallback POST.
                    for _ in range(2):
                        connection,_=listener.accept();accepted.append(time.monotonic())
                        with connection:stop.wait(delay/1000)
                except OSError:
                    if not stop.is_set():raise
            thread=threading.Thread(target=hold);thread.start()
            try:
                payload=json.dumps([dict(args=["fm-fetch-config",f["invites"]["wss"]])]).encode()
                with patch.dict(os.environ,SSL_CERT_FILE=str(certificate)):
                    started=time.monotonic();p=invoke(TEST,["--fetch-config-run"],root,payload,timeout=8);elapsed=time.monotonic()-started
                assert p.returncode==0,"config connect entry"
                result=json.loads(p.stdout)[0]
                assert result["status"]==1 and not result["stdout"] and result["stderr"],"config connect clean refusal"
                assert len(result["calls"])==2 and len(accepted)==2,"config connect GET POST"
                if delay==1100:
                    assert all(c["transport"]=="timeout" for c in result["calls"]),"config connect deadline before total deadline"
                elif delay==900:
                    assert all(c["transport"]=="error" for c in result["calls"]),"config below connect deadline"
                print(f"config connect {delay}ms: {elapsed:.3f}s; bounded handshake refusal",flush=True)
            finally:
                stop.set();listener.close();thread.join(timeout=6)
                assert not thread.is_alive(),"config held socket reaped"
    print("config connect controls: 3/3",flush=True)



def connect_contention():
    """Three finite controls with four bounded CPU children on two CPUs."""
    affinity = os.sched_getaffinity(0)
    workers = []
    program = "import time; deadline=time.monotonic()+75\nwhile time.monotonic()<deadline: sum(range(1000))"
    try:
        os.sched_setaffinity(0, sorted(affinity)[:2])
        for _ in range(4):
            workers.append(subprocess.Popen([sys.executable,"-B","-c",program],stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        for _ in range(3): connect_deadlines()
        assert all(p.poll() is None for p in workers), "config contention remained active"
        print("config connect modest contention: 3/3 controls; four bounded CPU children on two CPUs",flush=True)
    finally:
        for child in workers:
            if child.poll() is None: child.terminate()
        for child in workers: child.wait(timeout=5)
        os.sched_setaffinity(0, affinity)


def main():
    if sys.argv[1:]==["--generate"]:generate();return 0
    if sys.argv[1:2]==["--inside"]:
        if len(sys.argv)==4 and sys.argv[2]=="--probe":
            if sys.argv[3].startswith("guard-"):guardian_guards(sys.argv[3])
            else:replay(sys.argv[3])
        elif sys.argv[2:]==["--http"]:http_capabilities()
        elif sys.argv[2:]==["--connect"]:connect_deadlines()
        elif sys.argv[2:]==["--connect-contention"]:connect_contention()
        else:assert sys.argv[1:]==["--inside"];replay();parser_and_guards();guardian_guards();http_capabilities();connect_deadlines()
        return 0
    return network.run_isolated([sys.executable,"-B",str(Path(__file__).resolve()),"--inside",*sys.argv[1:]],timeout=300)


if __name__=="__main__":sys.exit(main())
