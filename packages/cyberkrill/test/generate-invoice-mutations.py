#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compiled LNURL runtime detections through the existing restoration runner."""
import hashlib
import importlib
import json
import sys
from cases import APP

M = importlib.import_module("price-mutations")
DEST = APP / "test/golden/ln-generate-mutation-record.json"


def mutations():
    app = "Cyberkrill/App.lean"
    flow = "Cyberkrill/GenerateInvoice.lean"
    url = "../lightning/Lightning/Lnurl/Url.lean"
    def probe(name): return ["python3","-B","test/generate-invoice.py","--probe",name]
    rows = [
        ("minimum-range",flow,"amount.msat < pay.minSendable.msat", "false",probe("below"),"LNURL refusal below"),
        ("inclusive-maximum",flow,"amount.msat > pay.maxSendable.msat", "amount.msat >= pay.maxSendable.msat",probe("maximum"),"LNURL success maximum"),
        ("comment-utf8-bytes",flow,"text.toUTF8.size > limit", "text.length > limit",probe("byte-over"),"LNURL refusal byte-over"),
        ("original-query",url,'let query := originalQuery.getD ""', 'let query := (originalQuery.map (fun _ => "")).getD ""',probe("sats"),"LNURL success sats"),
        ("form-encoding",url,'"&comment=" ++ formEncode s', '"&comment=" ++ s',probe("unicode"),"LNURL success unicode"),
        ("trailing-query-separator",url,'if query.isEmpty then "" else "&"',
            'if query.isEmpty || query.endsWith "&" then "" else "&"',probe("trailing-query"),"LNURL success trailing-query"),
        ("millisat-precision",app,'convertAmounts services #[parsed] .millisat', 'convertAmounts services #[parsed] .wholeSat',probe("fiat-at"),"LNURL success fiat-at"),
        ("dispatch",app,'return .generateInvoice address.value amount.value (flag "comment") (flag "output")',
            'return .decodeLnurl (some address.value) (flag "output")',probe("sats"),"LNURL success sats"),
    ]
    rows += [
        ("initial-url-normalization",flow,'Lightning.lightningAddressUrl address >>= Lightning.Lnurl.normalizeUrl',
         'Lightning.lightningAddressUrl address',probe("address-space"),"LNURL success address-space"),
        ("redirect-follow",flow,'[301, 302, 303, 307, 308].contains response.status.toNat',
         'false',probe("redirect-well-302"),"LNURL success redirect-well-302"),
        ("callback-redirect-follow",flow,'[301, 302, 303, 307, 308].contains response.status.toNat',
         'false',probe("redirect-callback"),"LNURL success redirect-callback"),
        ("redirect-limit",flow,'getResponse request url 10',
         'getResponse request url 9',probe("redirect-ten"),"LNURL success redirect-ten"),
        ("redirect-relative-resolution",url,'String.intercalate "/" (pathBase.splitOn "/").dropLast',
         'origin',probe("redirect-limit"),"LNURL refusal redirect-limit"),
    ]
    rows.append(("redirect-guard", "Cyberkrill/TestEntry.lean",
        'unless TestUrls.permitted req.url true && !TestUrls.forbiddenPort req.url do',
        'unless true do', [".lake/build/bin/CyberkrillTests", "--generate-invoice-ordering"],
        "LNURL redirected guard before transport"))
    rows.append(("redirect-uri-syntax",url,
        'if !uriReferenceValid location then return none', 'if false then return none',
        probe("redirect-invalid-path"),"LNURL success redirect-invalid-path"))
    rows.append(("redirect-raw-query",url,
        'serializeParts source true', 'serializeParts source false',
        probe("redirect-raw-query"),"LNURL success redirect-raw-query"))
    rows.append(("initial-normalization-guard","Cyberkrill/TestEntry.lean",
        '| .error _ => throw (.onchain "testLnurlRefused: Explicit loopback Lightning address is required")',
        '| .error _ => pure ()',probe("guard-invalid-initial"),"LNURL refusal guard-invalid-initial"))
    rows.append(("response-number-bound",flow,
        'unless numbersBounded text do throw (.lightning "malformedResponse: JSON")',
        'unless true do throw (.lightning "malformedResponse: JSON")',
        probe("well-numeric-limit"),"LNURL refusal well-numeric-limit"))
    rows.append(("callback-path-work",url,
        '  let count := pieces.length\n  let mut reversed : List String := []\n  for (piece, index) in pieces.drop 1 |>.zipIdx do\n    let dot := (Bitcoin.Bech32.lower piece).replace "%2e" "."\n    if dot == "." || dot == ".." then\n      if dot == ".." then reversed := reversed.drop 1\n      if index + 2 == count then reversed := "" :: reversed\n    else reversed := urlEscape true piece :: reversed\n  return "/" ++ String.intercalate "/" reversed.reverse\n',
        '  let mut stack : List String := []\n  for (piece, index) in pieces.drop 1 |>.zipIdx do\n    let dot := (Bitcoin.Bech32.lower piece).replace "%2e" "."\n    if dot == "." || dot == ".." then\n      if dot == ".." then stack := stack.dropLast\n      if index + 2 == pieces.length then stack := stack ++ [""]\n    else stack := stack ++ [urlEscape true piece]\n  return "/" ++ String.intercalate "/" stack\n',
        ["python3","-B","test/generate-invoice.py","--path-stress"],
        "LNURL large callback normalization exceeds 10s budget"))
    rows.append(("serialization-query-work",url,
        '  let parts ← parseUrlComponents source\n  let cleaned :=',
        '  let parts ← parseUrl source\n  let cleaned :=',
        ["python3","-B","test/generate-invoice.py","--query-stress"],
        "LNURL large query normalization exceeds 10s budget"))
    rows.append(("url-decimal-work",url,
        'if significant.length > maxDigits then none',
        'if significant.length > maxDigits && false then none',
        ["python3","-B","test/generate-invoice.py","--url-number-stress"],
        "LNURL large URL numeric parsing exceeds 10s budget"))
    assert len(rows)==21, "LNURL runtime mutation inventory"
    return rows


def fingerprints():
    paths = ["Cyberkrill/App.lean","Cyberkrill/GenerateInvoice.lean","Cyberkrill/TestEntry.lean",
        "CyberkrillTests/GenerateInvoice.lean","CyberkrillTests.lean","../lightning/Lightning/Lnurl/Url.lean",
        "test/generate-invoice.py","test/generate-invoice-mutations.py","test/network.py",
        "../lightning/LightningTests/Lnurl.lean",
        "test/price-mutations.py","test/http/ln-generate.json","test/http/ln-generate-expected.json",
        "test/http/ln-generate.provenance.json"]
    return {p:hashlib.sha256((APP/p).read_bytes()).hexdigest() for p in paths}


def verify():
    record = json.loads(DEST.read_bytes())
    assert record["source_sha256"]==fingerprints(), "stale LNURL runtime evidence"
    assert len(record["checks"])==len(mutations())==21, "LNURL detecting count"
    for check,row in zip(record["checks"],mutations()):
        assert [check[k] for k in ["property","file","replace","with_text","command","assertion"]]==list(row), "LNURL mutation identity"
        assert [check[k]["status"] for k in ["build","red","restore_build","green"]]==[0,1,0,0], "LNURL compiled/runtime/restored statuses"
        assert row[-1] in check["failure"] and ("AssertionError:" in check["failure"] or "assertion failed:" in check["failure"]), "LNURL intended runtime assertion"
    assert all(record[k]["status"]==0 for k in ["initial_build","initial_green","restored_full"])
    print("LNURL mutations: 21/21 compiled intended runtime reds; 21/21 restored builds and greens",flush=True)


if __name__ == "__main__":
    if sys.argv[1:]==["--verify"]: verify()
    else:
        assert not sys.argv[1:]
        M.DEST=DEST; M.mutations=mutations; M.fingerprints=fingerprints; M.verify=verify
        M.main(["python3","-B","test/generate-invoice.py"])
