#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent compiled bound and continuation controls with exact restoration."""
import hashlib
import importlib
import json
import sys
from cases import APP

M=importlib.import_module("price-mutations")
DEST=APP/"test/golden/fetch-config-mutation-record.json"


def mutations():
    flow="Cyberkrill/FetchConfig.lean";app="Cyberkrill/App.lean";entry="Cyberkrill/TestEntry.lean"
    def probe(name):return ["python3","-B","test/fetch-config.py","--probe",name]
    def success(name):return "config success "+name
    rows=[
        ("numeric-token",flow,'if token.length > 2048 then','if false then',probe("token-2049"),success("token-2049")),
        ("numeric-coefficient",flow,'if (parts.head!.replace "." "").length > 1024 then','if false then',probe("coefficient-1025"),success("coefficient-1025")),
        ("numeric-exponent",flow,'if digits.length > 4 || digits.toNat?.getD 0 > 1024 then','if false then',probe("exponent-1025"),success("exponent-1025")),
        ("container-depth",flow,'if depth ≥ 128 then','if false then',probe("array-depth-128"),success("array-depth-128")),
        ("finite-number-range",flow,'unless finiteNumber token do','unless true do',probe("ignored-overflow"),success("ignored-overflow")),
        ("transport-bytes",flow,'maxResponseBytes := 1048576','maxResponseBytes := 1048577',probe("bytes-1048577"),'config transport body bound'),
        ("injected-bytes",flow,'if r.body.size > req.maxResponseBytes.toNat then','if false then',probe("injected-bytes-1048577"),success("injected-bytes-1048577")),
        ("connect-deadline",flow,'connectTimeoutMs := 1000','connectTimeoutMs := 0',
         ["python3","-B","test/fetch-config.py","--connect"],'config connect deadline before total deadline'),
        ("total-deadline",flow,'totalTimeoutMs := 2000','totalTimeoutMs := 0',probe("total-2100"),success("total-2100")),
        ("location-work",flow,'if location.utf8ByteSize > 8192 then','if false then',probe("location-limit"),success("location-limit")),
        ("resolved-url-work",flow,'if req.url.utf8ByteSize > 8192 then','if false then',probe("resolved-url-limit"),success("resolved-url-limit")),
        ("utf8-before-json",flow,'let some text := String.fromUTF8? r.body | throw (.decode "fmUtf8Decode")',
         'let text := Lightning.Lnurl.lossyUtf8 r.body',probe("utf8-next"),success("utf8-next")),
        ("get-status-post",flow,'if successful r then pure get else','if true then pure get else',probe("get-status-post"),success("get-status-post")),
        ("get-transport-post",flow,'| .error _ => response request { req with\n        method := .post, body := some "{}".toUTF8\n        headers := #[("Content-Type", "application/json")] } 10',
         '| .error e => pure (.error e)',probe("get-transport-post"),success("get-transport-post")),
        ("post-body-header",flow,'headers := #[("Content-Type", "application/json")] } 10\n    | .error _',
         'headers := #[] } 10\n    | .error _',probe("get-status-post"),success("get-status-post")),
        ("decode-next",flow,'| .error e => last := e.message','| .error e => return .error (failure e.message)',probe("non-json-next"),success("non-json-next")),
        ("post-decode-next",flow,'| .error e => last := e.message','| .error e => return .error (failure e.message)',probe("post-json-next"),success("post-json-next")),
        ("post-status-next",flow,'| .error e => last := e.message','| .error e => return .error (failure e.message)',probe("post-status-next"),success("post-status-next")),
        ("first-success",flow,'return parseConfig config invite.federationId','let _ := parseConfig config invite.federationId\n        pure ()',probe("first-success"),success("first-success")),
        ("weak-missing-id",flow,'| none => return true','| none => throw (failure "fmFederationIdType")',probe("absent-id"),success("absent-id")),
        ("stable-peers",flow,'guardians := guardians.reverse.mergeSort (fun a b => a.1 ≤ b.1)',
         'guardians := guardians.mergeSort (fun a b => a.1 ≤ b.1)',probe("peers"),success("peers")),
        ("global-rewrite",flow,'(url.replace "wss://" "https://").replace "ws://" "http://"',
         'if url.startsWith "ws://" then "http://" ++ (url.drop 5).toString else url',probe("embedded"),success("embedded")),
        ("all-trailing-slashes",flow,'rewritten.toList.reverse.dropWhile (· == \'/\')',
         'if rewritten.endsWith "/" then rewritten.toList.reverse.drop 1 else rewritten.toList.reverse',probe("injected-double-slash"),success("injected-double-slash")),
        ("invite-fallback",flow,'let invite ← match InviteCli.decode input with',
         'let invite ← match (FedimintInvite.decode input).mapError (fun _ => Error.offline "invalidInvite") with',probe("fallback"),success("fallback")),
        ("dispatch",app,'return .fetchConfig invite.value (flag "output")','return .decodeInvite (some invite.value) (flag "output")',probe("get"),success("get")),
        ("retained-output-handle",app,'| .ok result => return .ok (lightningOutput result.pretty writer false)\n  | .generateInvoice',
         '| .ok result => return .ok (lightningOutput result.pretty none false)\n  | .generateInvoice',probe("retained-handle"),success("retained-handle")),
        ("redirect-follow",flow,'[301, 302, 303, 307, 308].contains r.status.toNat','false',probe("injected-get-redirect-302"),success("injected-get-redirect-302")),
        ("post-redirect-method",flow,'[301, 302, 303].contains r.status.toNat','false',probe("injected-post-redirect-302"),success("injected-post-redirect-302")),
        ("redirect-referer",flow,'.push ("Referer", referer)','',probe("injected-get-redirect-302"),success("injected-get-redirect-302")),
        ("redirect-limit",flow,'let get ← response request req 10','let get ← response request req 9',probe("injected-redirect-ten"),success("injected-redirect-ten")),
        ("redirect-guard",entry,'unless TestUrls.permitted req.url && !TestUrls.forbiddenPort req.url do',
         'unless true do',probe("unsafe-redirect-307"),'config refusal unsafe-redirect-307'),
    ]
    for name in ["missing-endpoints","id-mismatch","id-type"]:
        rows.append(("validation-abort-"+name,flow,
            'match validate config invite.federationId with\n      | .error e => return .error e',
            'match validate config invite.federationId with\n      | .error _ => pure ()',probe(name),'config refusal '+name))
    for name in ["array","null","bad-peer","peer-overflow","endpoint-type"]:
        rows.append(("semantic-abort-"+name,flow,'return parseConfig config invite.federationId',
            'match parseConfig config invite.federationId with\n        | .ok result => return .ok result\n        | .error _ => pure ()',probe(name),'config refusal '+name))
    assert len(rows)==39,"config compiled mutation inventory"
    return rows


def fingerprints():
    paths=["Cyberkrill/App.lean","Cyberkrill/FetchConfig.lean","Cyberkrill/Invite.lean","Cyberkrill/TestEntry.lean",
        "CyberkrillTests/FetchConfig.lean","CyberkrillTests.lean","test/network.py","test/fetch-config.py",
        "test/fetch-config-mutations.py","test/price-mutations.py","test/http/fetch-config.json",
        "test/http/fetch-config-reference.json","test/http/fetch-config.provenance.json",
        "../http-curl/HttpCurl.lean","../http-curl/link_shim.c","../http-curl/test/responder.py",
        "../lightning/Lightning/Lnurl/Url.lean"]
    return {p:hashlib.sha256((APP/p).read_bytes()).hexdigest() for p in paths}


def verify():
    record=json.loads(DEST.read_bytes())
    assert record["source_sha256"]==fingerprints(),"stale config runtime evidence"
    assert len(record["checks"])==len(mutations())==39,"config runtime detecting inventory"
    for check,row in zip(record["checks"],mutations()):
        assert [check[k] for k in ["property","file","replace","with_text","command","assertion"]]==list(row),"config mutation identity"
        assert [check[k]["status"] for k in ["build","red","restore_build","green"]]==[0,1,0,0],"config compiled/runtime/restored statuses"
        assert row[-1] in check["failure"] and ("AssertionError:" in check["failure"] or "assertion failed:" in check["failure"]),"config intended runtime assertion"
    assert all(record[k]["status"]==0 for k in ["initial_build","initial_green","restored_full"])
    print("config mutations: 39/39 compiled intended runtime reds; 39/39 restored builds and greens",flush=True)


if __name__=="__main__":
    if sys.argv[1:]==["--verify"]:verify()
    else:
        assert not sys.argv[1:]
        M.DEST=DEST;M.mutations=mutations;M.fingerprints=fingerprints;M.verify=verify
        M.main(["python3","-B","test/fetch-config.py"])
