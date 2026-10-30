#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Offline binding, independent completeness and real responder replay checks."""
import copy
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
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
RESPONSES = {"single-list": 10, "multisig-list": 10, "multipath-create": 9,
             "change-funded": 15, "move-overshoot": 13, "move-f64": 5, "move-success": 2, "dca": 11}
METHOD_COUNTS = {
    "single-list": dict(getdescriptorinfo=2, importdescriptors=2, deriveaddresses=2, listunspent=2),
    "multisig-list": dict(getdescriptorinfo=2, importdescriptors=2, deriveaddresses=2, listunspent=2),
    "multipath-create": dict(getdescriptorinfo=3, importdescriptors=1, deriveaddresses=2, listunspent=2, createpsbt=1),
    "change-funded": dict(getdescriptorinfo=5, importdescriptors=1, deriveaddresses=4, listunspent=2, getreceivedbyaddress=2, walletcreatefundedpsbt=1),
    "move-overshoot": dict(getdescriptorinfo=3, importdescriptors=1, deriveaddresses=2, listunspent=2, getrawtransaction=4, createpsbt=1),
    "move-f64": dict(getrawtransaction=3, createpsbt=2),
    "move-success": dict(getrawtransaction=1, createpsbt=1),
    "dca": dict(getblockchaininfo=1, scantxoutset=2, getrawtransaction=4, getblock=2),
}
METHODS = {"listunspent", "scantxoutset", "getblockchaininfo", "getdescriptorinfo", "importdescriptors",
           "deriveaddresses", "createpsbt", "getreceivedbyaddress", "walletcreatefundedpsbt", "getrawtransaction", "getblock"}
METHOD_INVENTORY = dict(listunspent=10, scantxoutset=2, getblockchaininfo=1,
                        getdescriptorinfo=15, importdescriptors=7, deriveaddresses=12,
                        createpsbt=5, getreceivedbyaddress=2, walletcreatefundedpsbt=1,
                        getrawtransaction=12, getblock=2)


def body(reply):
    assert reply["status"] == 200, "Core RPC HTTP200"
    value = parse_json(reply["text"])
    assert value["jsonrpc"] == "2.0" and value["id"] in [1, "cyberkrill"], "Core RPC2 envelope"
    assert ("result" in value) != ("error" in value), "Core result/error separation"
    return value


def result(entry):
    return body(entry["responses"][0]).get("result")


def check_selectors(entries):
    selectors = set()
    for entry in entries:
        for params in entry["rpc"]["params"]:
            key = (entry["method"], entry["path"], entry["rpc"]["method"], G.selector(params))
            assert key not in selectors, "overlapping exact selectors"
            selectors.add(key)


def expected_inputs(row, methods, descriptor, funding):
    """Independently reconstruct command inputs from case-local RPC replies.

    Never consult a PSBT request or the generator's expansion implementation.
    Source: bitcoin_rpc.rs:786-802,854-889,1329-1345 at the pinned revision.
    """
    expanded = []
    explicit = dict(zip(["{first}", "{second}", "{third}"], funding))
    for index, arg in enumerate(row["args"]):
        if arg != "--inputs": continue
        input = row["args"][index + 1]
        if input in explicit:
            expanded.append(explicit[input])
        else:
            assert input == "{descriptor}", "declared input expansion"
            seen = set()
            for branch in [0, 1]:
                desc = descriptor.replace("<0;1>", str(branch))
                info = next(e for e in methods["getdescriptorinfo"] if e["rpc"]["params"] == [[desc]])
                derive = next(e for e in methods["deriveaddresses"] if e["rpc"]["params"] == [[result(info)["descriptor"], [0, 99]]])
                entry = next(e for e in methods["listunspent"] if e["rpc"]["params"] == [[0, 9999999, result(derive)]])
                for utxo in result(entry):
                    key = (utxo["txid"], utxo["vout"])
                    if key in seen: continue
                    seen.add(key)
                    # Funding correspondence is checked independently before here.
                    expanded.append(next(p for p in funding if (p["txid"], p["vout"]) == key))
    if "--max-amount" in row["args"]:
        selected = []
        total = 0
        cap = G.sats(G.option(row, "--max-amount"))
        for p in sorted(expanded, key=lambda p: p["sats"], reverse=True):
            if total >= cap: break
            selected.append(p)
            total += p["sats"]
        expanded = selected
    return [dict(txid=p["txid"], vout=p["vout"]) for p in expanded]


def check_producers(rows, cases):
    producers = {cases[row["name"]]["capture"]["producer"] for row in rows if row["kind"] != "dca"}
    assert producers <= {"reference-proxy", "source-client"} and len(producers) <= 1, "consistent non-DCA producer policy"


def check_capture(row, meta):
    assert "reference_result" in meta and "first_case_attempts" in meta, "required capture attempt metadata"
    attempts = meta["first_case_attempts"]
    assert isinstance(attempts, list) and (0 if row["kind"] == "dca" else 1) <= len(attempts) <= 2, "bounded first-case attempts"

    def execution(value):
        assert isinstance(value, dict) and {"status", "stdout", "stderr"} <= value.keys(), "capture execution record"
        status = value["status"]
        assert type(status) in [int, Decimal] and Decimal(status).is_finite() and status == int(status), "capture execution record"
        assert all(isinstance(value[k], str) for k in ["stdout", "stderr"]), "capture execution record"
        assert "qualifying_capture" not in value or type(value["qualifying_capture"]) is bool, "capture execution record"

    for attempt in attempts: execution(attempt)
    reference = meta["reference_result"]
    if reference is not None: execution(reference)

    def history():
        assert all(a.get("qualifying_capture") is False for a in attempts[:-1]), "first-case retry evidence"
        if attempts[-1].get("qualifying_capture", True) is True:
            # The first case may be precision exit1, independently of this case.
            assert attempts[-1]["status"] in [0, 1], "first-case qualification status"
        elif row["kind"] == "dca":
            assert len(attempts) == 2 and attempts[0].get("qualifying_capture") is False, "fallback requires two failed reference attempts"

    if row["kind"] == "dca":
        # Full runs carry the first non-DCA attempts; DCA itself never runs it.
        assert reference is None, "DCA never executes reference"
        if attempts: history()
        return
    if meta["producer"] == "reference-proxy":
        assert reference is not None and reference["status"] != 124, "reference-proxy execution evidence"
        # Older successful captures have status/streams only. Their complete
        # case-local entries remain checked below; do not infer success from exit0.
        assert attempts[-1].get("qualifying_capture", True) is True, "reference first-case qualification"
        history()
    else:
        # Both preferred attempts must have failed to produce a qualifying capture.
        # A process can exit0 with incomplete capture, or exit1 with the intended
        # precision error. Preserve the capture decision separately from status.
        assert len(attempts) == 2 and all(a.get("qualifying_capture") is False for a in attempts), "fallback requires two failed reference attempts"
        assert reference is None or reference == {k: attempts[-1][k] for k in ["status", "stdout", "stderr"]}, "fallback per-case reference evidence"


def validate_case(row, data, shared):
    G.validate_definition(row)
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
    check_capture(row, meta)
    entries = data["entries"]
    assert G.digest(G.encoded(entries)) == meta["entries_sha256"], "capture response digest"
    assert len(entries) == COUNTS[row["name"]], "case entry completeness: " + row["name"]
    from collections import Counter
    assert Counter(e["rpc"]["method"] for e in entries) == METHOD_COUNTS[row["name"]], "case method inventory"
    assert sum(len(e["responses"]) for e in entries) == RESPONSES[row["name"]], "case response inventory"
    assert sum(len(e["rpc"]["params"]) for e in entries) == COUNTS[row["name"]], "case selector inventory"
    check_selectors(entries)
    for entry in entries:
        parsed = Entry(entry)  # The production responder parser, unchanged.
        assert entry["method"] == "POST" and entry["path"] == "/wallet/" + row["fixture"], "case-local endpoint"
        assert entry["authorization"] == G.AUTH and entry["unauthorized"]["status"] == 401, "disposable auth and real 401"
        assert entry["rpc"]["method"] in METHODS and entry.get("source"), "v1 source-traced method"
        assert len(parsed.variants) > 0, "nonempty exact variants"
        for reply in entry["responses"]: body(reply)
    descriptors = json.loads(shared["shared/descriptors.json"])
    descriptor = descriptors[row["fixture"]]
    methods = {m: [e for e in entries if e["rpc"]["method"] == m] for m in METHODS}
    exported = json.loads(shared["shared/frozenkrill-" + row["fixture"] + ".json"])
    prefix = "singlesig_" if row["fixture"] == "single" else ""
    assert exported["network"] == "regtest" and exported["version"] == 0, "public wallet reader network/version"
    assert exported["sigtype"] == ("singlesig" if row["fixture"] == "single" else "2-of-3"), "public wallet reader signature type"
    for branch, field in [(0, "receiving"), (1, "change")]:
        assert exported[prefix + field + "_output_descriptor"] == descriptor.replace("<0;1>", str(branch)), "wallet/descriptor correspondence"
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
    if row["kind"] in ["create", "funded", "move-success", "overshoot", "move-f64"]:
        expected = expected_inputs(row, methods, descriptor, funding)
        for method in ["createpsbt", "walletcreatefundedpsbt"]:
            for entry in methods[method]:
                for params in entry["rpc"]["params"]:
                    assert G.selector(params[0]) == G.selector(expected), "ordered case-local PSBT inputs: " + row["name"]
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
        floated = 0.0
        for p in funding[:3]: floated += int(p["sats"]) / 1e8
        floated -= G.sats(G.option(row, "--fee")) / 1e8
        assert list(original["rpc"]["params"][0][1].values()) == [Decimal(repr(floated))], "source-derived f64 arithmetic"
        assert body(original["responses"][0])["error"]["code"] == -3, "observed Core invalid amount"
        assert "Invalid amount" in body(original["responses"][0])["error"]["message"], "Core amount error message"
        sats = sum(int(p["sats"]) for p in funding[:3]) - G.sats(G.option(row, "--fee"))
        assert list(exact["rpc"]["params"][0][1].values()) == [Decimal(sats) / 100000000], "independent exact satoshi amount"
        assert result(exact).startswith("cHNidP"), "observed exact amount success"
        assert original["rpc"]["params"] != exact["rpc"]["params"], "float/exact request distinction"
    if row["kind"] == "dca":
        assert row["scan_range"] == [0, 200], "DCA declared range"
        assert meta["producer"] == "source-client" and meta["reference_result"] is None, "DCA never executes reference"
        assert len(methods["getblockchaininfo"]) == 1 and result(methods["getblockchaininfo"][0])["chain"] == "regtest", "DCA regtest height"
        assert len(methods["scantxoutset"]) == 2 and len(methods["getblock"]) == 2, "DCA branches/blocks"
        for branch, scan in enumerate(methods["scantxoutset"]):
            assert scan["rpc"]["params"] == [["start", [dict(desc=descriptor.replace("<0;1>", str(branch)), range=row["scan_range"])]]], "both scan ranges 0..200"
            scanned = result(scan)
            chain = result(methods["getblockchaininfo"][0])
            assert scanned["success"], "real completed scan"
            assert scanned["height"] == chain["blocks"] and scanned["bestblock"] == chain["bestblockhash"], "DCA scan chain snapshot"
            expected = funding[:3] if branch == 0 else funding[3:]
            assert {(u["txid"], u["vout"]) for u in result(scan)["unspents"]} == {(p["txid"], p["vout"]) for p in expected}, "DCA scan funding"
            assert scanned["total_amount"] == Decimal(sum(int(p["sats"]) for p in expected)) / 100000000, "DCA scan total amount"
            for index, p in enumerate(expected):
                utxo = next(u for u in scanned["unspents"] if (u["txid"], u["vout"]) == (p["txid"], p["vout"]))
                tx = result(next(e for e in methods["getrawtransaction"] if e["rpc"]["params"] == [[p["txid"], True]]))
                block = result(next(e for e in methods["getblock"] if e["rpc"]["params"] == [[tx["blockhash"]]]))
                assert utxo["amount"] == Decimal(p["sats"]) / 100000000 and utxo["scriptPubKey"] == tx["vout"][int(p["vout"])]["scriptPubKey"]["hex"], "DCA scan value/script correspondence"
                assert utxo["height"] == block["height"] and utxo["blockhash"] == block["hash"] and utxo["confirmations"] == tx["confirmations"], "DCA scan block correspondence"
                path = descriptors["paths"][0][2:].replace("'", "h")
                prefix = f"wpkh([{descriptors['fingerprint']}/{path}/{branch}/{index}]"
                assert utxo["desc"].startswith(prefix), "DCA derived descriptor origin"
                public_key = bytes.fromhex(utxo["desc"][len(prefix):].split(')')[0])
                assert len(public_key) == 33 and utxo["scriptPubKey"] == "0014" + hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).hexdigest(), "DCA descriptor script hash"
        dates = set()
        for txentry in methods["getrawtransaction"]:
            tx = result(txentry)
            blockentry = next(e for e in methods["getblock"] if e["rpc"]["params"] == [[tx["blockhash"]]])
            block = result(blockentry)
            assert block["hash"] == tx["blockhash"] and tx["txid"] in block["tx"], "DCA transaction/block correspondence"
            assert block["height"] in [102, 103] and tx["blocktime"] == block["time"], "DCA block height/time"
            assert block["height"] + tx["confirmations"] - 1 == result(methods["getblockchaininfo"][0])["blocks"], "DCA confirmation height"
            dates.add(datetime.fromtimestamp(int(block["time"]), timezone.utc).strftime("%Y-%m-%d"))
        assert dates == set(row["dates"]), "DCA fixed block dates"
    return entries


def validate_bundle(rows, blobs, shared):
    from collections import Counter
    assert set(blobs) == {r["recording"] for r in rows}, "recording file completeness"
    assert set(shared) == set(G.SHARED) and shared["bitcoin-dir/.cookie"] == G.COOKIE, "shared file completeness/auth"
    check_producers(rows, {r["name"]: parse_json(blobs[r["recording"]]) for r in rows})
    methods = set()
    inventory = Counter()
    total = 0
    responses = 0
    for row in rows:
        entries = validate_case(row, parse_json(blobs[row["recording"]]), shared)
        methods.update(e["rpc"]["method"] for e in entries)
        inventory.update(e["rpc"]["method"] for e in entries)
        total += len(entries)
        responses += sum(len(e["responses"]) for e in entries)
        print(f"RPC {row['name']}: {len(entries)}/{COUNTS[row['name']]} entries/selectors, "
              f"{sum(len(e['responses']) for e in entries)}/{RESPONSES[row['name']]} responses; "
              f"methods {METHOD_COUNTS[row['name']]}", flush=True)
    if {r["name"] for r in rows} == set(COUNTS):
        assert len(rows) == 8 and total == 69, "independent case/entry inventory"
        assert methods == METHODS, "eleven-method completeness"
        assert inventory == METHOD_INVENTORY and responses == 75, "complete method/response inventory"
        print(f"RPC recordings: {len(rows)}/8 cases, {len(methods)}/11 methods, {total}/69 entries", flush=True)
        print(f"RPC method inventory: {dict(inventory)}; {responses}/75 authorized responses", flush=True)


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
                wrong = copy.deepcopy(first)
                wrong["rpc"]["method"] = "unexpected-rpc-method"
                assert request(port, wrong, first["rpc"]["params"][0])[0] == 599, "unexpected RPC method refusal"
                expected_requests = 4
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
                cursor = 4
                for entry in data["entries"]:
                    for params in entry["rpc"]["params"]:
                        for observed in logged[cursor:cursor + len(entry["responses"]) + 2]:
                            payload = parse_json(observed["body"])
                            assert observed["method"] == entry["method"] and observed["path"] == entry["path"], "replay request method/path"
                            assert payload["method"] == entry["rpc"]["method"] and G.selector(payload["params"]) == G.selector(params), "replay exact request params"
                        cursor += len(entry["responses"]) + 2
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
