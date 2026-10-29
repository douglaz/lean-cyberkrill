#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent offline regressions with one isolated source edit per property."""
import copy
from contextlib import redirect_stdout
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
from unittest.mock import patch

G = importlib.import_module("generate-rpc-recordings")
R = importlib.import_module("rpc-recordings")
S = importlib.import_module("rpc-recording-safety")


def rejected(operation, assertion):
    try: operation()
    except (AssertionError, ValueError, KeyError) as error:
        assert assertion in str(error), "wrong detecting assertion: " + str(error)
    else: raise AssertionError("missing refusal: " + assertion)


def controls(g=G, r=R, s=S):
    rows = G.inventory()
    root = G.HERE / "recordings"
    shared = {name: (root / name).read_bytes() for name in G.SHARED}
    data = {row["name"]: G.parse_json((root / row["recording"]).read_bytes()) for row in rows}
    row = next(row for row in rows if row["name"] == "move-f64")
    value = data[row["name"]]
    def checked(value=value, row=row, shared=shared): r.validate_case(row, value, shared)
    def corrupt(edit, assertion):
        changed = copy.deepcopy(value)
        edit(changed)
        # Rebind the untrusted content digest so semantic tests reach their property.
        changed["capture"]["entries_sha256"] = G.digest(G.encoded(changed["entries"]))
        rejected(lambda: checked(changed), assertion)
    def definition_command():
        bad = {**row, "command": "onchain-list-utxos"}
        rejected(lambda: g.validate_definition(bad), "command/kind consistency")
    def definition_args():
        bad = {**row, "args": row["args"][:-2]}
        rejected(lambda: g.validate_definition(bad), "command argument shape")
    def arithmetic():
        class Collector:
            def __init__(self): self.calls = []
            def record(self, method, params, wallet): self.calls.append((method, params))
        collector = Collector()
        desc = json.loads(shared["shared/descriptors.json"])
        addresses = {"single": [["bcrt1-test"] * 6]}
        funding = [{**p, "sats": int(p["sats"]), "vout": int(p["vout"])} for p in value["capture"]["funding"]]
        g.fallback(collector, row, desc, addresses, funding)
        assert list(collector.calls[-1][1][1].values()) == [G.Decimal("0.6999833999999999")], "ordered source float regression"
    def key_scan():
        rejected(lambda: s.portable("sample.json", json.dumps({"data": "tprv" + "1" * 104}).encode()), "private extended key")
    def private_field():
        rejected(lambda: s.portable("sample.json", b'{"capture":{"seed":"forbidden"}}'), "private field")
    def metadata(): s.portable("move-f64.json", b'{"capture":{"tools":{"mnemonic":"0.21"}}}')
    def provenance_output():
        rejected(lambda: s.portable("shared/provenance.json", b'{"derivation":{"mnemonic":"forbidden phrase"}}'), "private field")
    def version_output():
        rejected(lambda: s.portable("shared/provenance.json", b'{"derivation":{"versions":{"mnemonic":"forbidden phrase"}}}'), "private field")
    def credentials():
        rejected(lambda: s.portable("sample.json", b'{"other":"Basic wrong"}'), "unexpected Basic credentials")
    def rpcauth():
        rejected(lambda: s.portable("sample.json", b'{"rpcauth":"lck:changed"}'), "unexpected rpcauth credentials")
    def home_path():
        rejected(lambda: s.portable("sample.json", b'{"data":"~/private-node"}'), "home-relative path")
    def selector():
        assert g.selector([9007199254740992]) != g.selector([9007199254740993]), "exact large-integer selector"
        assert g.selector([True]) != g.selector([1]), "boolean selector distinction"
        assert g.selector([1, 2]) != g.selector([2, 1]), "selector array order"
        assert g.selector([1]) == g.selector([G.Decimal("1.0")]), "exact numeric equivalence"
    def body():
        expected = value["entries"][0]["responses"][0]
        rejected(lambda: r.assert_response((expected["status"], expected["headers"], b"changed"), expected), "replay full response bytes")
    def headers():
        rejected(lambda: r.assert_response((200, {}, b"payload"), dict(status=200, headers={"x-required": "retained"}, text="payload")), "replay full retained headers")
    def status():
        rejected(lambda: r.assert_response((201, {}, b"payload"), dict(status=200, headers={}, text="payload")), "replay status")
    def overlap():
        entries = copy.deepcopy(value["entries"])
        entries[-1]["rpc"]["params"] = copy.deepcopy(entries[-2]["rpc"]["params"])
        rejected(lambda: r.check_selectors(entries), "overlapping exact selectors")
    def isolation():
        r.check_selectors(value["entries"])
        r.check_selectors(value["entries"])
    def method_inventory():
        corrupt(lambda d: d["entries"][0]["rpc"].update(method="getblock"), "case method inventory")
    def response_inventory():
        corrupt(lambda d: d["entries"][0]["responses"].append(copy.deepcopy(d["entries"][0]["responses"][0])), "case response inventory")
    def entry_inventory():
        corrupt(lambda d: d["entries"].pop(), "case entry completeness")
    def definition_binding():
        corrupt(lambda d: d["binding"].update(definition="0" * 64), "case definition binding")
    def shared_binding():
        corrupt(lambda d: d["binding"]["files"].update({"bitcoin-dir/.cookie": "0" * 64}), "case shared/auth binding")
    def endpoint():
        corrupt(lambda d: d["entries"][0].update(path="/wallet/multisig"), "case-local endpoint")
    def missing_recording():
        rejected(lambda: r.validate_bundle([row], {}, shared), "recording file completeness")
    def wallet():
        changed = dict(shared)
        export = json.loads(changed["shared/frozenkrill-single.json"])
        export["singlesig_receiving_output_descriptor"] = "changed"
        changed["shared/frozenkrill-single.json"] = G.encoded(export)
        changed_data = copy.deepcopy(value)
        changed_data["binding"]["files"] = {name: G.digest(blob) for name, blob in changed.items()}
        rejected(lambda: checked(changed_data, shared=changed), "wallet/descriptor correspondence")
    def shared_prelaunch():
        with tempfile.TemporaryDirectory(prefix="rpc-shared-", dir=os.environ["TMPDIR"]) as temp:
            destination = Path(temp) / "recordings"
            destination.mkdir()
            rejected(lambda: g.verify_shared(destination, shared), "selected shared drift")
            for name, blob in shared.items():
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(blob)
            (destination / "bitcoin-dir/.cookie").write_bytes(b"changed")
            rejected(lambda: g.verify_shared(destination, shared), "selected shared drift")
    def publication():
        with tempfile.TemporaryDirectory(prefix="rpc-publication-", dir=os.environ["TMPDIR"]) as temp:
            destination = Path(temp)
            for name in ["first.json", "second.json"]: (destination / name).write_bytes(b"original")
            mkstemp = tempfile.mkstemp
            count = 0
            def fail_second(*args, **kwargs):
                nonlocal count
                count += 1
                if count == 2: raise OSError("controlled staging failure")
                return mkstemp(*args, **kwargs)
            try:
                with patch.object(g.tempfile, "mkstemp", fail_second):
                    g.publish(destination, {"first.json": b"replacement", "second.json": b"replacement"})
            except OSError as error: assert str(error) == "controlled staging failure"
            else: raise AssertionError("staging failure must propagate")
            assert {p.name: p.read_bytes() for p in destination.iterdir()} == {"first.json": b"original", "second.json": b"original"}, "failed staging preserves published bytes"
    def dca_corrupt(edit, assertion):
        dca_row = next(row for row in rows if row["name"] == "dca")
        changed = copy.deepcopy(data["dca"])
        entry = next(e for e in changed["entries"] if e["rpc"]["method"] == "scantxoutset")
        reply = G.parse_json(entry["responses"][0]["text"])
        edit(reply["result"])
        entry["responses"][0]["text"] = G.json_text(reply) + "\n"
        changed["capture"]["entries_sha256"] = G.digest(G.encoded(changed["entries"]))
        rejected(lambda: r.validate_case(dca_row, changed, shared), assertion)
    def dca_chain(): dca_corrupt(lambda v: v.update(bestblock="0" * 64), "DCA scan chain snapshot")
    def dca_total(): dca_corrupt(lambda v: v.update(total_amount=v["total_amount"] + G.Decimal("0.00000001")), "DCA scan total amount")
    def dca_value(): dca_corrupt(lambda v: v["unspents"][0].update(amount=G.Decimal("0.00000001")), "DCA scan value/script correspondence")
    def dca_block(): dca_corrupt(lambda v: v["unspents"][0].update(height=0), "DCA scan block correspondence")
    def dca_origin(): dca_corrupt(lambda v: v["unspents"][0].update(desc=v["unspents"][0]["desc"].replace("[73c5da0a/", "[00000000/")), "DCA derived descriptor origin")
    def dca_hash():
        dca_row = next(row for row in rows if row["name"] == "dca")
        r.validate_case(dca_row, data["dca"], shared)
    return dict(command=definition_command, args=definition_args, arithmetic=arithmetic,
                key=key_scan, private=private_field, metadata=metadata, credentials=credentials,
                body=body, headers=headers, status=status, overlap=overlap,
                methods=method_inventory, responses=response_inventory, entries=entry_inventory,
                definition=definition_binding, shared=shared_binding, endpoint=endpoint,
                missing=missing_recording, wallet=wallet, selector=selector,
                prelaunch=shared_prelaunch, publication=publication, isolation=isolation,
                rpcauth=rpcauth, home_path=home_path, dca_chain=dca_chain,
                dca_total=dca_total, dca_value=dca_value, dca_block=dca_block,
                dca_origin=dca_origin, dca_hash=dca_hash,
                provenance_output=provenance_output, version_output=version_output)


def main():
    edits = [
        ("command", G, 'assert row["command"] == commands.get(row["kind"])', 'assert True'),
        ("args", G, 'assert len(row["args"]) == len(expected)', 'assert True'),
        ("arithmetic", G, 'for p in chosen: total += p["sats"] / 1e8', 'for p in chosen: total = p["sats"] / 1e8'),
        ("key", S, 'assert re.search(KEY_PATTERN, text) is None', 'assert True'),
        ("private", S, 'assert allowed, "private field in recording"', 'assert True, "private field in recording"'),
        ("metadata", S, 'or trail == ("capture", "tools")', 'or False'),
        ("credentials", S, 'obj == G.AUTH or challenge', 'True'),
        ("body", R, 'assert payload == expected["text"].encode()', 'assert True'),
        ("headers", R, 'assert all(folded.get(k.lower()) == v for k, v in expected["headers"].items())', 'assert True'),
        ("status", R, 'assert status == expected["status"]', 'assert True'),
        ("selector", G, 'return canonical(parse_json(json_text(value)))', 'return canonical(parse_json(json.dumps(json.loads(json_text(value), parse_int=float, parse_float=float))))'),
        ("responses", R, 'assert sum(len(e["responses"]) for e in entries) == RESPONSES[row["name"]]', 'assert True'),
        ("definition", R, 'assert data["binding"]["definition"] == G.digest(G.definition_bytes(row))', 'assert True'),
        ("shared", R, 'assert data["binding"]["files"] == {name: G.digest(value) for name, value in shared.items()}', 'assert True'),
        ("endpoint", R, 'assert entry["method"] == "POST" and entry["path"] == "/wallet/" + row["fixture"]', 'assert True'),
        ("wallet", R, 'assert exported[prefix + field + "_output_descriptor"] == descriptor.replace("<0;1>", str(branch))', 'assert True'),
        ("prelaunch", G, 'assert path.is_file() and not path.is_symlink() and path.read_bytes() == data', 'assert True'),
        ("publication", G, 'target.write(data); target.flush(); os.fsync(target.fileno())', 'target.write(data); target.flush(); os.fsync(target.fileno()); os.replace(temporary, path)'),
        ("overlap", R, 'assert key not in selectors', 'assert True'),
        ("isolation", R, 'selectors = set()', 'selectors = getattr(check_selectors, "seen", set()); check_selectors.seen = selectors'),
        ("rpcauth", S, 'assert name == "shared/provenance.json" and trail == ("auth",) and item == G.RPCAUTH', 'assert True'),
        ("home_path", S, 'assert not obj.startswith(("~/",', 'assert True or not obj.startswith(("~/",'),
        ("dca_chain", R, 'assert scanned["height"] == chain["blocks"] and scanned["bestblock"] == chain["bestblockhash"]', 'assert True'),
        ("dca_total", R, 'assert scanned["total_amount"] == Decimal(sum(int(p["sats"]) for p in expected)) / 100000000', 'assert True'),
        ("dca_value", R, 'assert utxo["amount"] == Decimal(p["sats"]) / 100000000 and utxo["scriptPubKey"] == tx["vout"][int(p["vout"])]["scriptPubKey"]["hex"]', 'assert True'),
        ("dca_block", R, 'assert utxo["height"] == block["height"] and utxo["blockhash"] == block["hash"] and utxo["confirmations"] == tx["confirmations"]', 'assert True'),
        ("dca_origin", R, 'assert utxo["desc"].startswith(prefix)', 'assert True'),
        ("dca_hash", R, 'hashlib.sha256(public_key)', 'hashlib.sha256(b"")'),
        ("provenance_output", S, 'and item == dict(', 'and True or item == dict('),
        ("version_output", S, 'version = key == "mnemonic" and item == "0.21"', 'version = key == "mnemonic"'),
    ]
    originals = {Path(module.__file__): Path(module.__file__).read_bytes() for module in [G, R, S]}
    records = []
    for name, module, old, new in edits:
        controls()[name]()
        source = originals[Path(module.__file__)].decode()
        assert source.count(old) == 1, "unique isolated source edit: " + name
        mutated = types.ModuleType(module.__name__)
        mutated.__file__ = module.__file__
        exec(compile(source.replace(old, new, 1), module.__file__, "exec"), mutated.__dict__)
        kwargs = {"g" if module is G else "r" if module is R else "s": mutated}
        try:
            with redirect_stdout(io.StringIO()): controls(**kwargs)[name]()
        except AssertionError as error:
            failure = str(error)
            assert failure, "named detecting assertion"
            assert not failure.startswith("wrong detecting assertion"), failure
        else: raise AssertionError("undetected source mutation: " + name)
        controls()[name]()
        assert all(path.read_bytes() == data for path, data in originals.items()), "unchanged original source bytes"
        records.append(dict(property=name, file=Path(module.__file__).name, replace=old, with_text=new, status=1, failure=failure, restored=0))
        print(f"RPC mutation {name}: red 1 ({failure}); original green 0")
    # Actual recursive grep with a planted long key, in a disposable copy only.
    with tempfile.TemporaryDirectory(prefix="rpc-safety-copy-", dir=os.environ["TMPDIR"]) as temp:
        import shutil
        root = Path(temp) / "recordings"
        shutil.copytree(G.HERE / "recordings", root)
        S.scan(root)
        path = root / "move-f64.json"
        path.write_bytes(path.read_bytes() + b'\ntprv' + b'1' * 104)
        rejected(lambda: S.scan(root), "recording safety grep requires exit 1")
        rejected(lambda: S.scan(root / "absent"), "real recording directory required")
    logs = G.HERE.parent / ".lake/validation"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "rpc-mutations.json").write_text(json.dumps(dict(count=len(records), edits=records,
        source_sha256={p.name: hashlib.sha256(b).hexdigest() for p, b in originals.items()}), indent=2) + "\n")
    for name, check in controls().items(): check()
    assert len(records) == 30, "independent mutation count"
    print("RPC source mutations: 30/30 detecting reds and restored greens; separate planted-key and missing-path refusals")


if __name__ == "__main__": main()
