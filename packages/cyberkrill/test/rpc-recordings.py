#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Offline binding, independent completeness and real responder replay checks."""
import copy
from datetime import datetime, timezone
from decimal import Decimal
import http.client
import importlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile

G = importlib.import_module("generate-rpc-recordings")
from responder import Entry, canonical, json_text, parse_json

COUNTS = {"single-list": 8, "multisig-list": 8, "multipath-create": 9,
          "change-funded": 15, "move-overshoot": 13, "move-f64": 5, "move-success": 2, "dca": 9}
METHODS = {"listunspent", "scantxoutset", "getblockchaininfo", "getdescriptorinfo", "importdescriptors",
           "deriveaddresses", "createpsbt", "getreceivedbyaddress", "walletcreatefundedpsbt", "getrawtransaction", "getblock"}


def body(reply):
    assert reply["status"] == 200, "Core RPC HTTP200"
    value = parse_json(reply["text"])
    assert value["jsonrpc"] == "2.0" and value["id"] in [1, "cyberkrill"], "Core RPC2 envelope"
    assert ("result" in value) != ("error" in value), "Core result/error separation"
    return value


def result(entry):
    return body(entry["responses"][0]).get("result")


def validate_case(row, data, shared):
    assert data["case"] == row["name"] and data["schema"] == 1, "case identity/schema"
    assert data["binding"]["definition"] == G.digest(G.definition_bytes(row)), "case definition binding"
    assert data["binding"]["files"] == {name: G.digest(value) for name, value in shared.items()}, "case shared/auth binding"
    meta = data["capture"]
    import re
    assert all(re.fullmatch(r"[0-9a-f]{40}", meta[k]) for k in ["source_revision", "nixpkgs"]), "historical capture revisions"
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", meta["core"]), "historical Core version"
    assert all(re.fullmatch(r"[0-9a-f]{64}", v) for v in meta["source_sha256"].values()), "historical source digests"
    assert all(re.fullmatch(r"[0-9a-f]{64}", meta[k]) for k in ["generator_sha256", "reference_sha256"]), "historical producer digests"
    assert meta["producer"] in ["reference-proxy", "source-client"], "capture producer"
    assert meta["wallet_private_keys_enabled"] is False, "watch-only capture"
    assert set(meta["tools"]) == {"mnemonic", "bip32", "coincurve", "base58"} and all(isinstance(v, str) and v for v in meta["tools"].values()), "historical tool versions"
    entries = data["entries"]
    assert G.digest(G.encoded(entries)) == meta["entries_sha256"], "capture response digest"
    assert len(entries) == COUNTS[row["name"]], "case entry completeness: " + row["name"]
    selectors = set()
    for entry in entries:
        parsed = Entry(entry)  # The production responder parser, unchanged.
        assert entry["method"] == "POST" and entry["path"] == "/wallet/" + row["fixture"], "case-local endpoint"
        assert entry["authorization"] == G.AUTH and entry["unauthorized"]["status"] == 401, "disposable auth and real 401"
        assert entry["rpc"]["method"] in METHODS and entry.get("source"), "v1 source-traced method"
        assert len(parsed.variants) > 0, "nonempty exact variants"
        for params in parsed.variants:
            key = (entry["method"], entry["path"], entry["rpc"]["method"], params)
            assert key not in selectors, "overlapping exact selectors"
            selectors.add(key)
        for reply in entry["responses"]: body(reply)
    descriptors = json.loads(shared["shared/descriptors.json"])
    descriptor = descriptors[row["fixture"]]
    methods = {m: [e for e in entries if e["rpc"]["method"] == m] for m in METHODS}
    funding = meta["funding"]
    assert [p["sats"] for p in funding] == list(map(G.sats, row["funding"])), "funding size plan"
    assert all(p["address"].startswith("bcrt1") and len(p["txid"]) == 64 for p in funding), "public regtest funding"
    if row["kind"] in ["list", "create", "funded", "overshoot"]:
        for branch in [0, 1]:
            expanded = descriptor.replace("<0;1>", str(branch))
            infos = [e for e in methods["getdescriptorinfo"] if e["rpc"]["params"] == [[expanded]]]
            assert len(infos) == 1, "both declared descriptor branches"
            checked = result(infos[0])["descriptor"]
            assert checked.split('#')[0] == expanded, "recorded descriptor correspondence"
            derived = [e for e in methods["deriveaddresses"] if e["rpc"]["params"] == [[checked, [0, 99]]]]
            assert len(derived) == 1 and len(result(derived[0])) == 100, "both address-expansion ranges"
            addresses = result(derived[0])
            unspents = [e for e in methods["listunspent"] if e["rpc"]["params"] == [[0, 9999999, addresses]]]
            assert len(unspents) == 1, "address-filtered listunspent shape"
            expected = funding[:3] if branch == 0 else funding[3:]
            assert {(p["txid"], p["vout"], Decimal(p["sats"]) / 100000000) for p in expected} == {
                (u["txid"], u["vout"], u["amount"]) for u in result(unspents[0])}, "list funding correspondence"
        assert methods["importdescriptors"], "import attempt retained"
        originals = [descriptor.replace("<0;1>", str(b)) for b in [0, 1]] if "--wallet-file" in row["args"] else [descriptor]
        assert len(methods["importdescriptors"]) == len(originals), "wallet split versus original multipath import count"
        for original in originals:
            info = next(e for e in methods["getdescriptorinfo"] if e["rpc"]["params"] == [[original]])
            expected = [[dict(desc=result(info)["descriptor"], timestamp="now", range=[0, 1000], watchonly=True, label="cyberkrill_import")]]
            assert any(e["rpc"]["params"] == [expected] for e in methods["importdescriptors"]), "source-shaped original descriptor import"
        assert any(any(not item["success"] and "error" in item for item in result(e)) for e in methods["importdescriptors"]), "real ignored import error retained"
    if row["kind"] in ["create", "funded", "move-success", "overshoot"]:
        name = "walletcreatefundedpsbt" if row["kind"] == "funded" else "createpsbt"
        assert len(methods[name]) == 1, "successful PSBT command shape"
        entry = methods[name][0]
        value = result(entry)
        psbt = value["psbt"] if isinstance(value, dict) else value
        assert isinstance(psbt, str) and psbt.startswith("cHNidP"), "real successful PSBT"
        params = entry["rpc"]["params"][0]
        assert params[2] == 0 and (params[3] is False if name == "createpsbt" else params[3]["fee_rate"] == 1), "PSBT locktime/options"
        expected_amount = {"create": Decimal("0.01"), "funded": Decimal("0.01"), "move-success": Decimal("0.39999"), "overshoot": Decimal("0.4999834")}[row["kind"]]
        assert list(params[1].values()) == [expected_amount], "exact command output amount"
    if row["kind"] == "funded":
        probes = methods["getreceivedbyaddress"]
        assert len(probes) == 2 and [result(p) for p in probes] == [Decimal("0.03"), 0], "used/unused change probe"
        params = methods["walletcreatefundedpsbt"][0]["rpc"]["params"][0]
        assert params[3]["changeAddress"] == probes[1]["rpc"]["params"][0][0], "funded change selection"
    if row["kind"] in ["overshoot", "move-f64", "move-success", "dca"]:
        expected = funding if row["kind"] in ["overshoot", "dca"] else funding[:3] if row["kind"] == "move-f64" else funding[:1]
        assert len(methods["getrawtransaction"]) == len(expected), "verbose transaction completeness"
        for p in expected:
            replies = [e for e in methods["getrawtransaction"] if e["rpc"]["params"] == [[p["txid"], True]]]
            assert len(replies) == 1, "verbose source params"
            tx = result(replies[0])
            assert tx["txid"] == p["txid"] and tx["vout"][int(p["vout"])]["value"] == Decimal(p["sats"]) / 100000000, "verbose funding value"
            assert tx["vout"][int(p["vout"])]["scriptPubKey"]["address"] == p["address"], "verbose funding address"
    if row["kind"] == "overshoot":
        params = methods["createpsbt"][0]["rpc"]["params"][0]
        assert params[0] == [dict(txid=p["txid"], vout=p["vout"]) for p in funding[:2]], "largest-first selection"
        assert sum(p["sats"] for p in funding[:2]) == 60000000 > 50000000, "selection overshoots cap"
    if row["kind"] == "move-f64":
        pair = methods["createpsbt"]
        assert len(pair) == 2, "distinct float/error and exact/success selectors"
        original, exact = pair
        floated = sum(float(p["sats"]) / 1e8 for p in funding[:3]) - G.sats(G.option(row, "--fee")) / 1e8
        assert list(original["rpc"]["params"][0][1].values()) == [Decimal(repr(floated))], "source-derived f64 arithmetic"
        assert body(original["responses"][0])["error"]["code"] == -3, "observed Core invalid amount"
        assert "Invalid amount" in body(original["responses"][0])["error"]["message"], "Core amount error message"
        sats = sum(int(p["sats"]) for p in funding[:3]) - G.sats(G.option(row, "--fee"))
        assert list(exact["rpc"]["params"][0][1].values()) == [Decimal(sats) / 100000000], "independent exact satoshi amount"
        assert result(exact).startswith("cHNidP"), "observed exact amount success"
        assert original["rpc"]["params"] != exact["rpc"]["params"], "float/exact request distinction"
    if row["kind"] == "dca":
        assert meta["producer"] == "source-client" and meta["reference_result"] is None, "DCA never executes reference"
        assert len(methods["getblockchaininfo"]) == 1 and result(methods["getblockchaininfo"][0])["chain"] == "regtest", "DCA regtest height"
        assert len(methods["scantxoutset"]) == 2 and len(methods["getblock"]) == 2, "DCA branches/blocks"
        for branch, scan in enumerate(methods["scantxoutset"]):
            assert scan["rpc"]["params"] == [["start", [dict(desc=descriptor.replace("<0;1>", str(branch)), range=[0, 200])]]], "both scan ranges 0..200"
            assert result(scan)["success"], "real completed scan"
            expected = funding[:3] if branch == 0 else funding[3:]
            assert {(u["txid"], u["vout"]) for u in result(scan)["unspents"]} == {(p["txid"], p["vout"]) for p in expected}, "DCA scan funding"
        dates = set()
        for txentry in methods["getrawtransaction"]:
            tx = result(txentry)
            blockentry = next(e for e in methods["getblock"] if e["rpc"]["params"] == [[tx["blockhash"]]])
            block = result(blockentry)
            assert block["hash"] == tx["blockhash"] and tx["txid"] in block["tx"], "DCA transaction/block correspondence"
            dates.add(datetime.fromtimestamp(int(block["time"]), timezone.utc).strftime("%Y-%m-%d"))
        assert dates == set(row["dates"]), "DCA fixed block dates"
    return entries


def validate_bundle(rows, blobs, shared):
    assert set(blobs) == {r["recording"] for r in rows}, "recording file completeness"
    assert set(shared) == set(G.SHARED) and shared["bitcoin-dir/.cookie"] == G.COOKIE, "shared file completeness/auth"
    methods = set()
    total = 0
    for row in rows:
        entries = validate_case(row, parse_json(blobs[row["recording"]]), shared)
        methods.update(e["rpc"]["method"] for e in entries)
        total += len(entries)
    if {r["name"] for r in rows} == set(COUNTS):
        assert len(rows) == 8 and total == 69, "independent case/entry inventory"
        assert methods == METHODS, "eleven-method completeness"
        print(f"RPC recordings: {len(rows)}/8 cases, {len(methods)}/11 methods, {total}/69 entries", flush=True)


def request(port, entry, params, authorization=G.AUTH, method="POST", path=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path or entry["path"], json_text(dict(jsonrpc="2.0", id=1, method=entry["rpc"]["method"], params=params)),
                     {"Content-Type": "application/json", "Authorization": authorization})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally: conn.close()


def assert_response(actual, expected):
    status, headers, payload = actual
    assert status == expected["status"], "replay status"
    assert payload == expected["text"].encode(), "replay full response bytes"
    folded = {k.lower(): v for k, v in headers.items()}
    assert all(folded.get(k.lower()) == v for k, v in expected["headers"].items()), "replay full retained headers"


def replay(path, data):
    with tempfile.TemporaryDirectory(prefix="rpc-replay-", dir=os.environ["TMPDIR"]) as directory:
        log = Path(directory) / "requests.jsonl"
        with open(Path(directory) / "stderr", "wb") as errors:
            process = subprocess.Popen([sys.executable, "-B", str(G.ROOT / "packages/http-curl/test/responder.py"), str(path), "--log", str(log)],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
            try:
                assert select.select([process.stdout], [], [], 10)[0], "replay startup deadline"
                ready = process.stdout.readline().decode().split()
                assert len(ready) == 3 and ready[0] == "READY", "real responder startup"
                port = int(ready[1])
                first = data["entries"][0]
                for kwargs in [dict(method="GET"), dict(path="/wallet/other"), dict(params=["unexpected-exact-variant"])]:
                    params = kwargs.pop("params", first["rpc"]["params"][0])
                    assert request(port, first, params, **kwargs)[0] == 599, "unexpected request/variant refusal"
                expected_requests = 3
                for entry in data["entries"]:
                    for params in entry["rpc"]["params"]:
                        assert_response(request(port, entry, params, authorization="Basic invalid"), entry["unauthorized"])
                        expected_requests += 1
                        for reply in entry["responses"]:
                            assert_response(request(port, entry, params), reply)
                            expected_requests += 1
                        assert request(port, entry, params)[0] == 599, "replay response exhaustion"
                        expected_requests += 1
                logged = [json.loads(line) for line in log.read_bytes().splitlines()]
                assert len(logged) == expected_requests, "complete case-local replay request log"
                assert all(r["path"] in [first["path"], "/wallet/other"] for r in logged), "case-local replay log paths"
            finally:
                process.stdin.close()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                process.stdout.close()
                assert process.returncode == 0, "replay child reaped"


def main():
    rows = G.inventory()
    assert {r["name"] for r in rows} == set(COUNTS), "pinned case inventory"
    root = G.HERE / "recordings"
    shared = {name: (root / name).read_bytes() for name in G.SHARED}
    assert {p.name for p in root.glob("*.json")} == {r["recording"] for r in rows}, "exact recording file set"
    blobs = {r["recording"]: (root / r["recording"]).read_bytes() for r in rows}
    validate_bundle(rows, blobs, shared)
    for row in rows: replay(root / row["recording"], parse_json(blobs[row["recording"]]))
    print("RPC replay: 8/8 separate real responders; exact params/auth, complete replies, refusals and exhaustion")


if __name__ == "__main__": main()
