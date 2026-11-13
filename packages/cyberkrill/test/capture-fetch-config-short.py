#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture the pinned config command against owned synthetic loopback replies."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile

from cases import APP, PIN
from evidence import write_record
import network

C=importlib.import_module("fetch-config")


def delivery_probe(root):
    """Observe libcurl's header callback through its CLI dump-header operation.

    Source: curl 8.22.0 lib/http.c, http_rw_hd/http_header/unfold_header and
    checkprotoprefix; lib/http_chunks.c, CHUNK_TRAILER and its 4096-byte dynbuf.
    These checks qualify only transformations/refusals before callback delivery.
    """
    environment=dict(os.environ,HOME=str(root/"home"),TMPDIR=str(root),PYTHONDONTWRITEBYTECODE="1")
    version=network.run_owned(["curl","--version"],capture_output=True,timeout=10,env=environment)
    assert version.returncode==0 and b"libcurl/8.22.0 " in version.stdout,"pinned callback probe version"
    selected={"unfolded-header":0,"folded-header":0,"folded-location":0,
              "interim-fold":0,"conflicting-location":8,"leading-blank":1,
              **{"trailer-field-bytes-"+str(n):0 if n==4095 else 100 for n in [4095,4096,4097,16381]},
              "trailer-bytes-16383":0}
    # The CLI's max-filesize also rejects large *declared* lengths. Those
    # acquisition boundaries use the actual legacy/detailed FFI controls;
    # this bounded dump probe qualifies library body-handling members only.
    selected.update({r["name"]:(61 if r["name"]=="body-gzip-refusal" else
                              56 if r["name"]=="body-chunk-width-17" else
                              8 if r["name"].startswith("body-bad-length-") else 0)
                     for r in C.body_cases() if not r["name"].startswith("body-length-") or r["name"]=="body-length-equal"})
    results=[]
    for row in C.header_cases()+C.parity_cases()+C.body_cases():
        name=row["name"]
        if name not in selected:continue
        network.refuse_spawn(["fm-fetch-config",C.fixtures()["invites"]["two"]],C.BASE)
        args=["curl","--noproxy","*","--silent","--show-error","--connect-timeout","1",
              "--max-time","3","--max-filesize","1048576","--dump-header",str(root/"headers"),
              "--output",str(root/"body"),C.BASE+"/first/config"]
        (root/"headers").write_bytes(b"")
        (root/"body").write_bytes(b"")
        with C.responder(root,[row["steps"][0]]) as log:
            result=network.run_owned(args,capture_output=True,timeout=10,env=environment)
            trace=[json.loads(line) for line in log.read_text().splitlines()]
        delivered=(root/"headers").read_bytes()
        body=(root/"body").read_bytes()
        assert result.returncode==selected[name] and not result.stdout,"callback probe status "+name
        assert trace==C.expected_trace(row["steps"][:1]),"callback probe trace "+name
        if name=="leading-blank":
            # The delimiter reaches the callback; the status/head after it do
            # not. The library refuses that response before it can be parsed.
            assert delivered==b"\r\n","blank status refused before head delivery"
        elif name=="conflicting-location":
            assert b"Location: /a\r\n" in delivered and b"Location: /b" not in delivered and not delivered.endswith(b"\r\n\r\n"),"conflicting Location refused before delivery"
        elif name in ["folded-header","folded-location","interim-fold"]:
            assert (b"Location: /fold\r\n" if name=="folded-location" else b"X-Test: first second\r\n") in delivered,"fold joined before delivery "+name
            assert b"\r\n second" not in delivered and b"Location:\r\n" not in delivered,"no original folded line delivered "+name
        elif name.startswith("trailer-field-bytes-"):
            assert b"\r\n\r\n" in delivered,"trailer limit follows complete final head"
            assert (b"X: " in delivered)==(selected[name]==0),"single trailer refused before field delivery "+name
        if name.startswith("body-"):
            wire=C.base64.b64decode(row["steps"][0]["response"]["wire"])
            assert len(wire)<1048576,"bounded authored delivery probe"
            head,wire_body=wire.split(b"\r\n\r\n",1)
            head+=b"\r\n\r\n"
            ordinary=next(r for r in C.body_cases() if r["name"]=="body-length-equal")
            config=C.base64.b64decode(ordinary["steps"][0]["response"]["wire"]).split(b"\r\n\r\n",1)[1]
            if name=="body-gzip-refusal":
                assert delivered==b"HTTP/1.1 200 Synthetic\r\n" and not body,"unrequested coding refused before delivery"
            elif name.startswith("body-bad-length-"):
                prefix=b"HTTP/1.1 200 Synthetic\r\n"+(b"Transfer-Encoding: chunked\r\n" if name.endswith("after") else b"")
                assert delivered==prefix and not body,"malformed length refused before delivery "+name
            elif name=="body-lf-trailer":
                assert delivered==head+b"X-Test: x\r\n" and body==config,"LF trailer normalized before delivery"
            else:
                assert delivered==head,"body framing headers delivered "+name
                expected=(b"" if name in ["body-length-204","body-length-304","body-dechunk-zero","body-dechunk-extension","body-chunk-width-17"] else
                          config[:-1] if name.startswith("body-cut-") and name.endswith("short") else config)
                assert body==expected,"body transformed before delivery "+name
            if name=="body-dechunk-extension":
                zero=next(r for r in results if r["name"]=="body-dechunk-zero")
                assert C.base64.b64decode(zero["headers_base64"])==delivered and C.base64.b64decode(zero["body_base64"])==body,"zero and extension lose original chunk framing"
        results.append(dict(name=name,status=result.returncode,stdout=result.stdout.decode(),stderr=result.stderr.decode(),
                            headers_base64=C.base64.b64encode(delivered).decode(),body_base64=C.base64.b64encode(body).decode(),requests=trace))
        print("callback delivery "+name+": exit "+str(result.returncode),flush=True)
    assert len(results)==len(selected)==32,"callback delivery inventory"
    return dict(version=version.stdout.decode().splitlines()[0],
                source="https://github.com/curl/curl/tree/curl-8_22_0/lib",
                paths=["http.c:3418-3434,4396-4423,4565-4596","http_chunks.c:CHUNK_TRAILER,4096-byte trailer dynbuf",
                       "content_encoding.c:780-808,827-854 (transfer decoder selection)",
                       "http_chunks.c:125-135,140-149,199-214,245-280 (delivery, width and trailers)",
                       "http_chunks.h:34-39 (CHUNK_MAXNUM_LEN)",
                       "http.c:3274-3320,3643-3662,3832-3855 (length refusal and cutting)",
                       "sendf.c:156-162,227-283 (length-limited delivery)"],
                command=["curl","--noproxy","*","--dump-header","$TMP_ROOT/headers","--output","$TMP_ROOT/body","owned loopback URL"],
                checks=results)


def capture(executable, completed):
    assert network.isolated(), "reference config capture requires a new network namespace"
    f=C.fixtures(); observations=[]
    rows=C.short_cases()+C.header_cases()+C.parity_cases()+C.body_cases()
    assert len(rows)==95, "reference acquired-response inventory"
    # Reference numeric refusals can move to a second guardian where exact
    # arithmetic accepts the first. Keep both canned endpoints ready in those
    # controls; observations record actual requests rather than predicting them.
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary);(root/"home").mkdir()
        for row in rows:
            steps=list(row["steps"])
            steps.extend(row.get("available",[]))
            if row.get("alternate") and not any(s["method"]=="POST" for s in steps): steps.append(row["alternate"])
            if row.get("invite")=="two" and not any(s["path"]=="/second/config" for s in steps):
                steps.append(dict(method="GET",path="/second/config",body="",response=dict(body=json.dumps(C.ready_config(f,row)))))
            args=["fm-fetch-config",f["invites"][row.get("invite","single")]]
            network.refuse_spawn(args,C.BASE)
            with C.responder(root,steps) as log:
                result=C.invoke(executable,args,root,timeout=20)
                requests=[json.loads(line) for line in log.read_text().splitlines()]
            assert requests==C.expected_trace(row["steps"]), "reference short-body stage " + row["name"]
            stdout=result.stdout.decode();stderr=result.stderr.decode()
            if row.get("error"):
                assert result.returncode!=0 and stderr and not stdout, "reference expected rejection " + row["name"]
            else:
                assert result.returncode==0 and stdout and not stdout.endswith("\n"), "reference independent success " + row["name"]
                if not row.get("warning"):
                    assert not stderr, "reference success stderr " + row["name"]
            observations.append(dict(name=row["name"],status=result.returncode,stdout=stdout,stderr=stderr,requests=requests))
            print("reference config "+row["name"]+": exit "+str(result.returncode),flush=True)
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        root=Path(temporary);(root/"home").mkdir()
        delivery=delivery_probe(root)
    parser_observations=[]
    for row in C.output_parser_cases():
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
            root=Path(temporary);(root/"home").mkdir()
            args=["fm-fetch-config",*row["args"]]
            network.refuse_spawn(args,C.BASE)
            with C.responder(root,[]) as log:
                result=C.invoke(executable,args,root,timeout=20)
                requests=[json.loads(line) for line in log.read_text().splitlines()]
            files=sorted(name for name in ["-x","-h","--help","a=b"] if (root/name).exists())
            assert result.returncode in [1,2] and result.stderr and not result.stdout and not requests,"reference output parser execution "+row["name"]
            assert all((root/name).read_bytes()==b"" for name in files),"reference empty output attachment"
            parser_observations.append(dict(name=row["name"],status=result.returncode,stdout=result.stdout.decode(),stderr=result.stderr.decode(),files=files,requests=requests))
            print("reference config parser "+row["name"]+": exit "+str(result.returncode)+"; files "+repr(files),flush=True)
    record=dict(source="https://github.com/douglaz/cyberkrill",revision=PIN,licence="MIT",kind="independent pinned CLI capture on authored synthetic complete/incomplete response bodies, LF framing, folded fields, interim/final headers, malformed trailers and offline output parsing; fedimint-lite/src/lib.rs:499-524; MIT",
                command=["fm-fetch-config","synthetic invite from fetch-config.json"],
                fixture_sha256=hashlib.sha256(C.FIXTURE.read_bytes()).hexdigest(),
                cases_sha256=hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest(),
                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),captures=observations,
                parser_cases_sha256=hashlib.sha256(json.dumps(C.output_parser_cases(),sort_keys=True).encode()).hexdigest(),parser_captures=parser_observations,
                delivery=delivery)
    write_record(C.APP/"test/http/fetch-config-short-reference.json",json.dumps(record,indent=2)+"\n")
    provenance = dict(source=record["source"],revision=PIN,licence="MIT",origin="Authored synthetic HTTP framing controls, folded fields, interim/final headers, malformed trailers and malformed-invite output parsing on the owned fixed-port responder; fedimint-lite/src/lib.rs:499-524.",
        capture_sha256=hashlib.sha256((C.APP/"test/http/fetch-config-short-reference.json").read_bytes()).hexdigest())
    write_record(C.APP/"test/http/fetch-config-short.provenance.json",json.dumps(provenance,indent=2)+"\n")
    completed.write_text("complete\n")
    print(f"reference config captures: {len(observations)+len(parser_observations)}/{len(rows)+len(C.output_parser_cases())}",flush=True)


def main():
    if sys.argv[1:2]==["--inside"]:
        assert len(sys.argv)==4;capture(sys.argv[2],Path(sys.argv[3]));return 0
    assert not sys.argv[1:]
    result=network.run_owned(["nix","build","--no-link","--print-out-paths","github:douglaz/cyberkrill/"+PIN],timeout=1200,capture_output=True)
    assert result.returncode==0,result.stderr.decode()
    executable=Path(result.stdout.decode().strip())/"bin/cyberkrill"
    assert executable.is_file(), "pinned reference binary"
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
        completed=Path(temporary)/"completed"
        status=network.run_isolated([sys.executable,"-B",str(Path(__file__).resolve()),"--inside",str(executable),str(completed)],timeout=600)
        assert status==0 and completed.is_file() and completed.read_text()=="complete\n", "reference capture ran without SKIP"
    return 0


if __name__=="__main__":sys.exit(main())
