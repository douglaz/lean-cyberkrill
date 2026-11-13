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
        ("production-connect-default",flow,'connectTimeoutMs : UInt32 := 10000','connectTimeoutMs : UInt32 := 10001',probe("get-status-post"),'config success get-status-post transport settings'),
        ("production-total-default",flow,'totalTimeoutMs : UInt32 := 60000','totalTimeoutMs : UInt32 := 60001',probe("injected-get-redirect-302"),'config success injected-get-redirect-302 transport settings'),
        ("connect-deadline",flow,'connectTimeoutMs := limits.connectTimeoutMs','connectTimeoutMs := 0',
         ["python3","-B","test/fetch-config.py","--connect-contention"],'config connect deadline before total deadline'),
        ("total-deadline",flow,'totalTimeoutMs := limits.totalTimeoutMs','totalTimeoutMs := 0',probe("total-2100"),success("total-2100")),
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
    rows.append(("acquired-body-next",flow,
        'if r.body.size > req.maxResponseBytes.toNat then',
        'if r.bodyError.isSome then return .error (.transport "fmTransport")\n  if r.body.size > req.maxResponseBytes.toNat then',
        probe("short-length-200"),success("short-length-200")+" raw request trace"))
    previous_guard = '        expected = urlsplit(stub_url or "")\n        # Inspect decoded invite material before creating a child. The guarded\n        # app entry separately checks decoded guardians and every redirect.\n        for token in args[1:]:\n            for material in url_material(token):\n                for match in re.finditer(r"(?:wss?|https?)://[^\\x00-\\x20\\x7f-\\xff]+", material):\n                    target = match[0].replace("wss://", "https://").replace("ws://", "http://")\n                    try:\n                        parsed = urlsplit(target)\n                        valid = (parsed.hostname == expected.hostname == "127.0.0.1" and\n                                 parsed.port == expected.port and parsed.port not in {None, 0, 8332} and\n                                 parsed.username is None and parsed.password is None)\n                    except ValueError:\n                        valid = False\n                    if not valid:\n                        raise ValueError("spawn refused: explicit stub guardian required")\n'
    guarded_targets = '        for token in args[1:]:\n            for target in effective_guardians(token):\n                if not permitted_guardian(target, stub_url):\n                    raise ValueError("spawn refused: explicit stub guardian required")\n'
    for name in ["guard-upper-first","guard-upper-later","guard-slashless-first","guard-slashless-later"]:
        rows.append((name,"test/network.py",guarded_targets,previous_guard,probe(name),'config no child '+name))
    rows.append(("legacy-transfer-error-order","../http-curl/HttpCurl.lean",
        'if code != 0 && (!detailed || !incomplete) then return .error (.curl code (← errorMessage code))',
        'if code != 0 && (!detailed || !incomplete) then\n    if !detailed && (String.fromUTF8? raw.headers).isNone then return .error (.curl 8 "Invalid response header encoding")\n    return .error (.curl code (← errorMessage code))',
        ["python3","-B","test/fetch-config.py","--http"], "config legacy transfer error before header decode"))
    rows.append(("final-response-headers","../http-curl/HttpCurl.lean",
        'result := { result with headers := #[] }',
        'result := result',probe("interim-location"),success("interim-location")+" raw request trace"))
    rows.append(("completed-headers-before-trailers","../http-curl/HttpCurl.lean",
        'finalHeadersComplete raw.headers',
        '(raw.headers.size >= 4 && raw.headers.extract (raw.headers.size - 4) raw.headers.size == "\\r\\n\\r\\n".toUTF8)',
        probe("complete-chunked-trailer"),success("complete-chunked-trailer")+" raw request trace"))
    rows.append(("trailers-not-redirect-headers","../http-curl/HttpCurl.lean",
        'if result.acquired then\n      if !line.isEmpty then',
        'if result.acquired then\n      if let some field := parseField line then result := { result with headers := result.headers.push field }\n      if !line.isEmpty then',
        probe("trailer-location"),success("trailer-location")+" raw request trace"))
    for name in ["output-short-flag","output-attached-equals"]:
        rows.append((name,app,
            '"fm-encode-invite", "fm-fetch-config", "onchain-decode-psbt", "onchain-list-utxos",',
            '"fm-encode-invite", "onchain-decode-psbt", "onchain-list-utxos",',
            probe(name),"config output parser "+name+" stage/files"))
    rows.append(("lf-acquisition","../http-curl/HttpCurl.lean",
        'if i ≥ 1 && bytes[i]! == 10 && (bytes[i - 1]! == 10 ||\n        (i ≥ 2 && bytes[i - 2]! == 10 && bytes[i - 1]! == 13)) then',
        'if i ≥ 3 && bytes[i - 3]! == 13 && bytes[i - 2]! == 10 &&\n        bytes[i - 1]! == 13 && bytes[i]! == 10 then',
        probe("lf-complete"),success("lf-complete")+" raw request trace"))
    rows.append(("lf-location","../http-curl/HttpCurl.lean",
        '| some field => result := { result with headers := result.headers.push field }',
        '| some field => if field.1 != "location" || wireSize == line.size + 2 then result := { result with headers := result.headers.push field }',
        probe("lf-redirect"),success("lf-redirect")+" raw request trace"))
    for name in ["short-length-200","short-chunked-200","post-body-failure"]:
        rows.append(("body-read-consumer-"+name,flow,
            'if r.bodyError.isSome then throw (.decode "fmBodyRead")',
            'if false then throw (.decode "fmBodyRead")',
            probe(name),success(name)+" raw request trace"))
    rows.append(("final-acquisition-latch","../http-curl/HttpCurl.lean",
        'if !complete && (i == 0 || bytes[i - 1]! == 10)',
        'if (i == 0 || bytes[i - 1]! == 10)',
        probe("status-trailer"),success("status-trailer")+" raw request trace"))
    rows.append(("final-header-extraction-latch","../http-curl/HttpCurl.lean",
        'if result.acquired then',
        'if result.acquired && line.extract 0 5 != "HTTP/".toUTF8 then',
        probe("status-trailer"),success("status-trailer")+" raw request trace"))
    rows.append(("malformed-trailer-body-error","../http-curl/HttpCurl.lean",
        'if invalidTrailer then some (.curl 8 "Invalid response trailer")',
        'if false then some (.curl 8 "Invalid response trailer")',
        probe("status-trailer"),success("status-trailer")+" raw request trace"))
    rows.append(("folded-header-no-post",flow,
        'if successful r then pure get else', 'if false then pure get else',
        probe("folded-header"),success("folded-header")+" raw request trace"))
    rows.append(("folded-location-follow",flow,
        '[301, 302, 303, 307, 308].contains r.status.toNat', 'false',
        probe("folded-location"),success("folded-location")+" raw request trace"))
    http="../http-curl/HttpCurl.lean"
    def rule(name,old,new,case,parser=False):
        rows.append((name,http,old,new,probe(("header-parser-" if parser else "")+case),
                     "config byte parser "+case if parser else success(case)+" raw request trace"))
    rule("field-name-token",'unless headerName name do none','unless headerName (name.replace "/" "") do none',"slash-name")
    rule("field-empty-name",'unless headerName name do none','unless name.isEmpty || headerName name do none',"empty-name")
    rule("field-colon-whitespace",'unless headerName name do none','unless headerName name.trimAscii.toString do none',"space-before-colon")
    rule("field-value-bytes",'unless value.data.all valueByte do none','unless true do none',"value-control")
    rule("head-field-capacity",'if fields > 100 then','if fields > 101 then',"final-fields-101")
    rule("interim-head-grammar",'| none => result := { result with invalidHead := true }\n      | some field',
         '| none => if !interimBlock then result := { result with invalidHead := true }\n      | some field',"interim-invalid-name")
    rule("trailer-field-grammar",'(parseField line).isNone || trailerCount','false || trailerCount',"trailer-slash")
    rule("trailer-field-count",'trailerCount ≥ 100','trailerCount ≥ 101',"trailer-fields-100")
    rule("trailer-aggregate-bytes",'trailerBytes + 2 ≥ 16384','trailerBytes + 2 ≥ 16385',"trailer-bytes-16384")
    rule("post-head-code-8",'let incomplete := acquired && code != 0','let incomplete := acquired && code != 0 && code != 8',"trailer-garbage")
    rule("post-head-code-100",'let incomplete := acquired && code != 0','let incomplete := acquired && code != 0 && code != 100',"trailer-field-bytes-4096")
    rule("header-utf8-acceptance",'let acquired := parsed.acquired && finalHeadersComplete raw.headers && !parsed.invalidHead',
         'let acquired := parsed.acquired && finalHeadersComplete raw.headers && !parsed.invalidHead && (String.fromUTF8? raw.headers).isSome',"nonutf8-value")
    rows.append(("first-location-byte-identity",flow,
        '(fields.find? (fun h => h.1 == "location")).bind (fun h => String.fromUTF8? h.2)',
        '(fields.filterMap (fun h => (String.fromUTF8? h.2).map (h.1, ·))).find? (fun h => h.1 == "location") |>.map (·.2)',
        probe("first-nonutf8-location-identity"),success("first-nonutf8-location-identity")))
    rule("status-code-delimiter",'unless line[12]! == 32 &&','unless (line[12]! == 32 || line[12]! == 48) &&',"status-four-digits",True)
    rule("status-version-delimiter",'unless line[8]! == 32 do none','unless line[8]! == 32 || line[8]! == 9 do none',"status-tab",True)
    rule("status-reason-bytes",'(line.extract 13 line.size).data.all valueByte','true',"reason-control",True)
    rule("content-length-overflow",'if n > 18446744073709551615 then return false\n      if n > 18446744073709551613 ||',
         'if false then return false\n      if false ||',"length-overflow",True)
    rule("content-length-digits","!part.toList.all (fun c => '0' ≤ c && c ≤ '9')",
         "!part.toList.all (fun c => ('0' ≤ c && c ≤ '9') || c == '+')","length-plus",True)
    rule("http10-framing",'then return !http10','then return true',"http10-transfer-encoding",True)
    rows.append(("reference-http1-negotiation","../http-curl/link_shim.c",
        'if (http1) SET(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);',
        'if (0) SET(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);',
        ["python3","-B","test/fetch-config.py","--http-alpn"],"config reference HTTP1 negotiation"))
    rule("successful-content-length-body",'else if shortContentLength raw.status parsed.headers raw.body.size then',
         'else if false then',"body-length-9223372036854775808")
    rows.append(("redirect-downgrade-prior-referer",flow,
        'let req := { req with headers := req.headers.filter (fun h => h.1.toLower != "referer") }',
        'let req := req',probe("redirect-downgrade-prior-referer"),
        "configuration redirect downgrade must omit prior Referer"))
    assert len(rows)==84,"config compiled mutation inventory"
    # Check new grammar/staging controls first, retaining every earlier identity.
    return rows[62:]+rows[:62]


def fingerprints():
    paths=["Cyberkrill/App.lean","Cyberkrill/FetchConfig.lean","Cyberkrill/Invite.lean","Cyberkrill/TestEntry.lean",
        "CyberkrillTests/FetchConfig.lean","CyberkrillTests.lean","test/network.py","test/fetch-config.py",
        "test/fetch-config-mutations.py","test/price-mutations.py","test/http/fetch-config.json",
        "test/http/fetch-config-reference.json","test/http/fetch-config.provenance.json",
        "test/capture-fetch-config-short.py","test/http/fetch-config-short-reference.json",
        "test/http/fetch-config-short.provenance.json",
        "../http-curl/HttpCurl.lean","../http-curl/link_shim.c","../http-curl/test/responder.py",
        "../lightning/Lightning/Lnurl/Url.lean"]
    return {p:hashlib.sha256((APP/p).read_bytes()).hexdigest() for p in paths}


def verify():
    record=json.loads(DEST.read_bytes())
    assert record["source_sha256"]==fingerprints(),"stale config runtime evidence"
    assert len(record["checks"])==len(mutations())==84,"config runtime detecting inventory"
    for check,row in zip(record["checks"],mutations()):
        assert [check[k] for k in ["property","file","replace","with_text","command","assertion"]]==list(row),"config mutation identity"
        assert [check[k]["status"] for k in ["build","red","restore_build","green"]]==[0,1,0,0],"config compiled/runtime/restored statuses"
        assert row[-1] in check["failure"] and ("AssertionError:" in check["failure"] or "assertion failed:" in check["failure"]),"config intended runtime assertion"
    assert all(record[k]["status"]==0 for k in ["initial_build","initial_green","restored_full"])
    print("config mutations: 84/84 compiled intended runtime reds; 84/84 restored builds and greens",flush=True)


if __name__=="__main__":
    if sys.argv[1:]==["--verify"]:verify()
    else:
        assert not sys.argv[1:]
        M.DEST=DEST;M.mutations=mutations;M.fingerprints=fingerprints;M.verify=verify
        M.main(["python3","-B","test/fetch-config.py"])
