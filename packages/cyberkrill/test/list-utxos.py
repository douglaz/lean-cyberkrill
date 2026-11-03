#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Public-export schema checks and isolated CLI replay, with exact JSON values."""
import copy
from decimal import Decimal
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cases import APP, ROOT, PIN, BUILD
from compare import differences, exact_json
import network

C = importlib.import_module("rpc-client")
G = C.G
R = C.R
HERE = APP / "test"
EXE = APP / ".lake/build/bin/cyberkrill"
DEST = HERE / "golden/list-utxos-reference.json"


def reader(value):
    payload = value if isinstance(value, bytes) else json.dumps(value).encode()
    return C.run(["--wallet-reader"], payload).strip()


def schemas():
    count = 0
    for kind in ["single", "multisig"]:
        original = json.loads((HERE / f"recordings/shared/frozenkrill-{kind}.json").read_bytes())
        prefix = "singlesig_" if kind == "single" else ""
        expected = dict(receiving=original[prefix + "receiving_output_descriptor"],
                        change=original[prefix + "change_output_descriptor"])
        def check(value, valid, label):
            nonlocal count
            result = reader(value)
            if valid:
                assert result != "invalidWallet", "wallet schema " + label
                assert json.loads(result) == expected, "wallet schema " + label
            else:
                assert result == "invalidWallet", "wallet schema " + label
            count += 1
        check(original, True, kind)
        for version in [1, 4294967295]:
            check(dict(original, version=version), True, "nonzero version")
        for key, value in original.items():
            altered = copy.deepcopy(original); del altered[key]
            check(altered, False, "required missing " + key)
            for wrong in [None, False, 4, {}, []] if isinstance(value, str) else [None, "wrong", False, {}]:
                check(dict(original, **{key: wrong}), False, "required type " + key)
        for key in ["version"]:
            for value in [-1, 4294967296, 1.5, "0"]:
                check(dict(original, **{key: value}), False, "u32 bounds")
        for token in ["1.0", "1e0", "0e0", "0.0", "-0"]:
            raw = json.dumps(original)
            assert raw.count('"version": 0') == 1, "public zero version"
            check(raw.replace('"version": 0', '"version": ' + token).encode(), False, "u32 lexical type")
        for value in ["", "other", "FROZENKRILL"]:
            check(dict(original, wallet=value), False, "wallet marker")
        if kind == "single":
            for value in ["SINGLESIG", "Singlesig"]:
                check(dict(original, sigtype=value), True, "sigtype case")
            check(dict(original, singlesig_xpub="merely a string", network="unvalidated",
                       master_fingerprint="", script_type="anything"), True, "permissive strings")
        else:
            for value in ["2of3", "2 of3", "2of 3", "2 OF 3", "prefix2-of-3suffix", "02-of-03", "15-of-15"]:
                check(dict(original, sigtype=value), True, "multisig spelling")
            for value in ["0-of-3 2-of-3", "4-of-3 2-of-3", "2-of-16", "4294967296-of-3", "2--of-3", "2\tof\t3", "2  of 3", "singlesig ", "invalid"]:
                check(dict(original, sigtype=value), False, "multisig rejection")
        for key in ["receiving_addresses", "change_addresses"]:
            for metadata in [{}, dict(index=None, derivation_path=None), dict(index=4294967295, derivation_path="anything")]:
                check(dict(original, **{key: [dict(address="synthetic", **metadata)]}), True, "address optional metadata")
            altered = dict(original, **{key: [dict(address="synthetic", index="negative-zero-token")]})
            raw = json.dumps(altered)
            assert raw.count('"negative-zero-token"') == 1, "unique synthetic index token"
            check(raw.replace('"negative-zero-token"', '-0').encode(), False, "address u32 lexical type")
            for value in [None, "wrong", [None], [{}], [dict(address=None)], [dict(address="synthetic", index=-1)],
                          [dict(address="synthetic", index=4294967296)], [dict(address="synthetic", derivation_path=2)],
                          [dict(address="synthetic", index=True)]]:
                check(dict(original, **{key: value}), False, "address schema")
    for value in [b"{", b"null", b"[]", b'{"wallet":"frozenkrill"}']:
        assert reader(value) == "invalidWallet", "wallet malformed JSON/discriminator"
        count += 1
    assert count == 249, "wallet schema inventory"
    print(f"wallet schema: {count} public-fixture/synthetic checks", flush=True)


def lexical(only=None):
    """Raw tokens preserve duplicates and escapes that a dictionary erases."""
    count = 0
    groups = {"duplicate-detector", "duplicate-schema", "duplicate-address",
              "string-root", "string-address", "string-key", "ignored"}
    assert only is None or only in groups
    for kind in ["single", "multisig"]:
        original = json.loads((HERE / f"recordings/shared/frozenkrill-{kind}.json").read_bytes())
        raw = json.dumps(original, ensure_ascii=False)
        def check(group, value, valid):
            nonlocal count
            if only and only != group: return
            result = reader(value.encode())
            assert (result != "invalidWallet") == valid, "wallet lexical " + group
            if valid: assert json.loads(result) == json.loads(reader(original)), "wallet lexical descriptors"
            count += 1
        for key in ["wallet", "version", "sigtype", "network", "receiving_addresses"]:
            group = "duplicate-detector" if key in {"wallet", "version", "sigtype"} else "duplicate-schema"
            encoded = json.dumps(original[key])
            escaped = '"\\u%04x%s"' % (ord(key[0]), key[1:])
            for name in [json.dumps(key), escaped]:
                for first, last in [(encoded, encoded), ("false", encoded), (encoded, "false")]:
                    # Remove the one original occurrence, then add two raw ones.
                    remaining = dict(original); del remaining[key]
                    value = '{' + name + ':' + first + ',' + json.dumps(key) + ':' + last + ',' + json.dumps(remaining)[1:]
                    check(group, value, False)
        prefix = "singlesig_" if kind == "single" else ""
        key = prefix + "receiving_output_descriptor"
        check("duplicate-schema", '{' + json.dumps(key) + ':' + json.dumps(original[key]) + ',' + raw[1:], False)
        for field, value in [("address", '"synthetic"'), ("derivation_path", '"m/0"'), ("index", "0")]:
            for first, last in [(value, value), ("false", value), (value, "false")]:
                nested = '{"address":"synthetic"}' if field != "address" else '{}'
                item = '{' + json.dumps(field) + ':' + first + ',"\\u%04x%s":' % (ord(field[0]), field[1:]) + last + (',' + nested[1:] if field != "address" else '}')
                altered = dict(original, receiving_addresses="raw-addresses-token")
                check("duplicate-address", json.dumps(altered).replace('"raw-addresses-token"', '[' + item + ']'), False)
        for token in ['"\\ud800"', '"\\udc00"', '"\\ud800x"', '"\\ud800\\u0041"', '"\\u12xz"', '"\\u123"', '"\\q"']:
            altered = dict(original, network="raw-string-token")
            check("string-root", json.dumps(altered).replace('"raw-string-token"', token), False)
            for field in ["address", "derivation_path"]:
                altered = dict(original, receiving_addresses=[dict(address="synthetic", **({field: "raw-string-token"} if field != "address" else {}))])
                if field == "address": altered["receiving_addresses"][0][field] = "raw-string-token"
                check("string-address", json.dumps(altered).replace('"raw-string-token"', token), False)
        for key in ['"\\ud800"', '"\\udc00"', '"\\ud800\\u0041"']:
            check("string-key", '{' + key + ':null,' + raw[1:], False)
            altered = dict(original, receiving_addresses="raw-addresses-token")
            check("string-key", json.dumps(altered).replace('"raw-addresses-token"', '[{"address":"synthetic",' + key + ':null}]'), False)
        for token in ['"\\ud83d\\ude00"', '"日本語"', '"\\u0061"']:
            check("string-root", json.dumps(dict(original, network="raw-string-token")).replace('"raw-string-token"', token), True)
            check("string-address", json.dumps(dict(original, receiving_addresses=[dict(address="raw-string-token")])).replace('"raw-string-token"', token), True)
            check("string-key", '{' + token + ':null,' + raw[1:], True)
        check("ignored", '{"unknown":false,"unknown":true,' + raw[1:], True)
        check("ignored", '{"unknown":"\\ud800","other":{"\\udc00":"\\ud800"},' + raw[1:], True)
        altered = dict(original, receiving_addresses="raw-addresses-token")
        check("ignored", json.dumps(altered).replace('"raw-addresses-token"', '[{"address":"synthetic","unknown":"\\ud800","unknown":null}]'), True)
        # The other schema's fields are ignored, including duplicate bad values.
        unused = "receiving_output_descriptor" if kind == "single" else "master_fingerprint"
        check("ignored", '{' + json.dumps(unused) + ':false,' + json.dumps(unused) + ':"\\ud800",' + raw[1:], True)
    if only is None: assert count == 160, "wallet lexical inventory"
    print(f"wallet lexical: {count} raw-token checks", flush=True)


def positional(only=None):
    """Synthetic derivatives of the public exports; raw slots retain lexical types."""
    count = 0
    groups = {"acceptance", "arity-short", "arity-long", "address-type", "path-type",
              "index-type", "address-escape", "path-escape", "unicode"}
    assert only is None or only in groups
    for kind in ["single", "multisig"]:
        original = json.loads((HERE / f"recordings/shared/frozenkrill-{kind}.json").read_bytes())
        expected = json.loads(reader(original))
        for key in ["receiving_addresses", "change_addresses"]:
            def check(group, slots, valid):
                nonlocal count
                if only and only != group: return
                raw = json.dumps(dict(original, **{key: "raw-slots-token"}))
                assert raw.count('"raw-slots-token"') == 1
                raw = raw.replace('"raw-slots-token"', '[' + slots + ']')
                result = reader(raw.encode())
                assert (result != "invalidWallet") == valid, "wallet positional " + group
                if valid: assert json.loads(result) == expected, "wallet positional descriptors"
                count += 1
            for slots in ['["synthetic",null,null]', '["synthetic","m/0",0]',
                          '["synthetic","anything",4294967295]']:
                check("acceptance", slots, True)
            for slots in ['[]', '["synthetic"]', '["synthetic",null]']:
                check("arity-short", slots, False)
            check("arity-long", '["synthetic",null,null,null]', False)
            for token in ['null', 'false', '4', '{}', '[]']:
                check("address-type", '[' + token + ',null,null]', False)
                if token != 'null': check("path-type", '["synthetic",' + token + ',null]', False)
            for token in ['"0"', 'true', '{}', '[]', '-1', '4294967296', '1.5', '1.0', '1e0', '0e0', '-0']:
                check("index-type", '["synthetic",null,' + token + ']', False)
            for token in ['"\\ud800"', '"\\udc00"', '"\\ud800x"', '"\\ud800\\u0041"', '"\\u12xz"', '"\\u123"', '"\\q"']:
                check("address-escape", '[' + token + ',null,null]', False)
                check("path-escape", '["synthetic",' + token + ',null]', False)
            for token in ['"\\ud83d\\ude00"', '"日本語"', '"\\u0061"']:
                check("unicode", '[' + token + ',null,null]', True)
                check("unicode", '["synthetic",' + token + ',null]', True)
    if only is None: assert count == 188, "wallet positional inventory"
    print(f"wallet positional: {count} raw-slot checks", flush=True)


def help_controls(only=None):
    count = 0
    with C.responder(HERE / "recordings/single-list.json") as (base, log, _):
        for left, right in [("--descriptor", "--addresses"), ("--descriptor", "--wallet-file"),
                            ("--addresses", "--wallet-file"), ("--bitcoin-dir", "--rpc-user"),
                            ("--bitcoin-dir", "--rpc-password")]:
            group = "source" if left != "--bitcoin-dir" else "credential"
            if only and only != group: continue
            for a, b in [(left, right), (right, left)]:
                for attached in [False, True]:
                    flags = [a + "=synthetic", b + "=synthetic"] if attached else [a, "synthetic", b, "synthetic"]
                    for suffix, status, error in [(["--help"], 0, b""), ([], 1, b"invalidArguments:" if group == "source" else b"rpcFlagConflict:")]:
                        result = network.checked_run(EXE, ["onchain-list-utxos", "--rpc-url", base, *flags, *suffix], stub_url=base, capture_output=True, timeout=10)
                        assert result.returncode == status and (bool(result.stdout) if status == 0 else result.stdout == b""), "list help conflict " + group
                        assert result.stderr == b"" if status == 0 else result.stderr.startswith(error), "list conflict error " + group
                        count += 1
        if only is None or only == "typed":
            for flag in ["--min-conf", "--max-conf"]:
                for attached in [False, True]:
                    flags = [flag + "=bad"] if attached else [flag, "bad"]
                    for suffix, status in [(flags + ["--help"], 1), (["--help"] + flags, 0)]:
                        result = network.checked_run(EXE, ["onchain-list-utxos", "--rpc-url", base, *suffix], stub_url=base, capture_output=True, timeout=10)
                        assert result.returncode == status, "list help typed ordering"
                        assert result.stderr.startswith(b"invalidConfirmations:") if status else result.stderr == b"", "list help typed diagnostic"
                        count += 1
        assert C.logged(log) == [], "list help/conflicts start no RPC"
    if only is None: assert count == 48, "list help inventory"
    print(f"list help/conflict/typed ordering: {count} checks; zero RPC", flush=True)


def split_controls():
    count = 0
    parent = APP / ".lake/list-split"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); output = root / "output.json"
        with C.responder(HERE / "recordings/single-list.json") as (base, log, _):
            # Malformed URL operands stay in injected tests: the endpoint guard
            # remains mandatory for every executable invocation.
            for flag in ["--descriptor", "--addresses", "--wallet-file", "--bitcoin-dir", "--rpc-user", "--rpc-password"]:
                for value in ["--help", "-x", "-abc", "--", "--output=unused"]:
                    for suffix in [[], ["--help"]]:
                        output.write_text("untouched sentinel")
                        args = ["onchain-list-utxos", "--rpc-url", base, "-o", str(output), flag, value, *suffix]
                        result = network.checked_run(EXE, args, stub_url=base, cwd=root, capture_output=True, timeout=10)
                        assert result.returncode != 0 and result.stdout == b"" and result.stderr.startswith(b"invalidArguments:"), "list executable split refusal"
                        assert output.read_text() == "untouched sentinel", "list split refusal preserves output"
                        count += 1
                for flags in [[flag + "=-x"], [flag, "-"], [flag, ""]]:
                    args = ["onchain-list-utxos", "--rpc-url", base, "--network", "bad", *flags]
                    result = network.checked_run(EXE, args, stub_url=base, cwd=root, capture_output=True, timeout=10)
                    assert result.returncode == 1 and result.stdout == b"" and result.stderr.startswith(b"invalidNetwork:"), "list executable split/attached positive"
                    count += 1
            assert C.logged(log) == [], "list split controls start no RPC"
    assert count == 78, "list executable split inventory"
    print(f"list split executable: {count} controls; output preserved on refusal; zero RPC", flush=True)


def matrix():
    rows = []
    for source, case in [("descriptor", "multipath-create"), ("single", "single-list"), ("multisig", "multisig-list")]:
        for bounds in [(1, 9999999), (1, 1), (2, 2), (3, 9999999), (2, 1)]:
            rows.append(dict(name=f"{source}-{bounds[0]}-{bounds[1]}", source=source, case=case, bounds=bounds, file=False))
    rows.append(dict(name="addresses", source="addresses", case="single-list", bounds=(0, 9999999), file=False))
    for source in ["single", "descriptor"]:
        rows.append(dict(name=source + "-file", source=source, case="single-list" if source == "single" else "multipath-create", bounds=(1, 9999999), file=True))
    assert len(rows) == 18, "list replay matrix inventory"
    return rows


def plan(row, root):
    data = R.parse_json((HERE / ("recordings/" + row["case"] + ".json")).read_bytes())
    entries = data["entries"]
    args = ["onchain-list-utxos", "--network", "regtest", "--min-conf", str(row["bounds"][0]), "--max-conf=" + str(row["bounds"][1])]
    lists = [e for e in entries if e["rpc"]["method"] == "listunspent"]
    if row["source"] == "addresses":
        addresses = lists[0]["rpc"]["params"][0][2]
        args += ["--addresses", " , " + ", ".join(addresses) + ", ,"]
        requests = [("listunspent", lists[0]["rpc"]["params"][0])]
        selected = [R.result(lists[0])]
    else:
        if row["source"] == "descriptor":
            args += ["--descriptor", entries[0]["rpc"]["params"][0][0]]
        else:
            path = root / "wallet.json"
            path.write_bytes((HERE / f"recordings/shared/frozenkrill-{row['source']}.json").read_bytes())
            args += ["--wallet-file", str(path)]
        requests = []
        for entry in entries:
            method = entry["rpc"]["method"]
            if method not in {"getdescriptorinfo", "importdescriptors", "deriveaddresses", "listunspent"}: continue
            if method == "getdescriptorinfo" and len(entry["responses"]) == 2:
                # One before import, then the same selector again after import.
                requests.append((method, entry["rpc"]["params"][0]))
            else: requests.append((method, entry["rpc"]["params"][0]))
            if method == "importdescriptors" and row["source"] != "descriptor":
                requests.append(("getdescriptorinfo", requests[-2][1]))
        selected = [R.result(e) for e in lists]
    utxos = []
    for group in selected:
        for raw in group:
            if row["source"] == "descriptor" and any(u["txid"] == raw["txid"] and u["vout"] == raw["vout"] for u in utxos): continue
            utxos.append(raw)
    if row["source"] != "addresses":
        lo, hi = row["bounds"]
        utxos = [u for u in utxos if lo <= u["confirmations"] <= hi]
    outputs = [dict(txid=u["txid"], vout=u["vout"], amount_sats=int(u["amount"] * Decimal(100000000)),
                    confirmations=u["confirmations"], spendable=u["spendable"], solvable=u["solvable"], safe=u["safe"],
                    address=u.get("address"), script_pub_key=u["scriptPubKey"], descriptor=u.get("descriptor")) for u in utxos]
    expected = dict(utxos=outputs, total_amount_sats=sum(u["amount_sats"] for u in outputs), total_count=len(outputs))
    if row["file"]: args += ["--output", str(root / "output.json")]
    return args, data, requests, expected


def one(row, reference=None, cookie=False, wallet_form=None):
    parent = APP / ".lake/list-utxos"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory)
        args, data, expected_requests, expected = plan(row, root)
        if wallet_form:
            assert reference is None and row["source"] in {"single", "multisig"}
            wallet = json.loads((root / "wallet.json").read_bytes())
            for key in ["receiving_addresses", "change_addresses"]:
                wallet[key] = [[item["address"], None, None] if wallet_form == "null" else
                               [item["address"], "synthetic metadata", 4294967295] for item in wallet[key]]
            (root / "wallet.json").write_text(json.dumps(wallet))
        path = HERE / ("recordings/" + row["case"] + ".json")
        with C.responder(path) as (base, log, _):
            url = base + data["entries"][0]["path"]
            args += ["--rpc-url", url]
            if cookie:
                (root / ".cookie").write_bytes((HERE / "recordings/bitcoin-dir/.cookie").read_bytes())
                args += ["--bitcoin-dir", str(root)]
            else: args += ["--rpc-user", "lck", "--rpc-password", "lck-throwaway"]
            env = os.environ.copy(); env["HOME"] = str(root)
            if reference:
                result = G.run([str(reference), *args], cwd=root, env=env, timeout=30, check=False, stub_url=url, reference=True)
            else:
                result = network.checked_run(EXE, args, stub_url=url, cwd=root, env=env,
                                             stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            status, stdout, stderr = result.returncode, result.stdout, result.stderr
            assert status == 0 and stderr == b"", "list CLI success " + row["name"] + ": " + stderr.decode(errors="replace")
            output = (root / "output.json").read_bytes() if row["file"] else stdout
            assert output and not output.endswith(b"\n"), "list no appended newline " + row["name"]
            assert (stdout == b"") == row["file"], "list stdout/file separation " + row["name"]
            assert not differences(exact_json(G.json_text(expected)), exact_json(output)), "list exact shape/nulls/order/filter/totals " + row["name"]
            observed = [(R.parse_json(r["body"])["method"], R.parse_json(r["body"])["params"]) for r in C.logged(log)]
            assert G.selector([list(r) for r in observed]) == G.selector([list(r) for r in expected_requests]), "list actual call parameters/order " + row["name"]
        return dict(name=row["name"], case=row["case"], source=row["source"], bounds=list(row["bounds"]),
                    file=row["file"], status=status, stdout=stdout.decode(), stderr=stderr.decode(),
                    file_bytes=output.decode() if row["file"] else None, requests=len(observed))


def positional_replay():
    count = 0
    captures = json.loads(DEST.read_bytes())["captures"]
    for kind in ["single", "multisig"]:
        row = next(r for r in matrix() if r["name"] == kind + "-1-9999999")
        reference = next(r for r in captures if r["name"] == row["name"])
        for form in [None, "null", "metadata"]:
            observed = one(row, wallet_form=form)
            assert not differences(exact_json(observed["stdout"]), exact_json(reference["stdout"])), "list positional pinned JSON parity"
            assert observed["requests"] == reference["requests"] == 10, "list positional complete call count"
            count += 1
    assert count == 6
    print("list positional replay: 6 object/sequence variants; same complete JSON and ordered calls as pinned captures", flush=True)


def failures():
    parent = APP / ".lake/list-errors"; parent.mkdir(parents=True, exist_ok=True)
    cases = [([], "missingSource"), (["--network", "bad"], "invalidNetwork"),
             (["--wallet-file", "missing.json"], "walletReadFailure"),
             (["--descriptor", "synthetic", "--bitcoin-dir", "unused"], "unsupportedBackend"),
             (["--addresses", "", "--descriptor", "synthetic"], "invalidArguments"),
             (["--wallet-file", "bad.json"], "invalidWallet")]
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); (root / "bad.json").write_text('{"wallet":"synthetic secret"}')
        # The closed owned responder port is never the node's default port.
        with C.responder(HERE / "recordings/single-list.json") as (base, _, closed):
            for extra, error in cases:
                path = root / "output.json"; path.write_text("truncate sentinel")
                args = ["onchain-list-utxos", "--rpc-url", base, "-o", str(path), *extra]
                proc = network.checked_run(EXE, args, stub_url=base, cwd=root, capture_output=True, timeout=10)
                assert proc.returncode == 1 and proc.stdout == b"" and proc.stderr.decode().startswith(error + ":"), "list named error " + error
                if error != "invalidArguments": assert path.read_bytes() == b"", "list truncate before " + error
                assert b"secret" not in proc.stderr and b"synthetic" not in proc.stderr, "list error suppression"
            proc = network.checked_run(EXE, ["onchain-list-utxos", "--rpc-url", base, "--network", "bad", "-o", str(root)], stub_url=base, cwd=root, capture_output=True, timeout=10)
            assert proc.returncode == 1 and proc.stderr.startswith(b"outputFailure:"), "list actual open failure before network"
    print("list CLI named failures/truncation/open precedence: 7/7", flush=True)


def synthetic(only=None):
    # All modifications below are explicitly synthetic orchestration controls,
    # never captured Core replies. Published fixture strings remain public.
    data = R.parse_json((HERE / "recordings/multipath-create.json").read_bytes())
    data["entries"] = data["entries"][:-1]
    descriptor = data["entries"][0]["rpc"]["params"][0][0]
    parent = APP / ".lake/list-synthetic"; parent.mkdir(parents=True, exist_ok=True)
    rows = ["derive-failure", "import-failure", "info-failure", "dedup", "precision", "size-large", "size-small", "timeout"]
    for name in rows:
        if only and only != name: continue
        fixture = copy.deepcopy(data)
        if name == "derive-failure":
            # First derive fails; listunspent([]) still runs, then change follows.
            fixture["entries"][3]["responses"] = [dict(status=200, json=dict(result=None, error=dict(code=-99, message="synthetic")))]
            fixture["entries"][4]["rpc"]["params"] = [[0, 9999999, []]]
        if name == "info-failure":
            fixture["entries"][2]["responses"] = [dict(status=200, json=dict(result=None, error=dict(code=-99, message="synthetic")))]
        if name == "import-failure":
            fixture["entries"][1]["responses"] = [dict(status=200, json=dict(result=None, error=dict(code=-99, message="synthetic")))]
        if name == "dedup":
            first = R.result(fixture["entries"][4])[0]
            reply = fixture["entries"][7]["responses"][0]
            reply["json"] = dict(result=[first, first], error=None)
            reply.pop("text", None)
        if name == "precision":
            entry = fixture["entries"][4]
            values = copy.deepcopy(R.result(entry))
            values[0]["amount"] = Decimal("90071992.54740993")
            entry["responses"] = [dict(status=200, json=dict(result=values, error=None))]
        if name.startswith("size-"):
            for entry in fixture["entries"]:
                if entry["rpc"]["method"] == "getdescriptorinfo":
                    for response in entry["responses"]:
                        body = response.get("text") or G.json_text(response["json"])
                        response.pop("json", None); response["text"] = " " * 1100000 + body
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            path = Path(directory) / "synthetic.json"; path.write_text(G.json_text(fixture))
            with C.responder(path, delay_ms=300 if name == "timeout" else 0) as (base, log, _):
                payload = dict(url=base + "/wallet/single", descriptor=descriptor,
                               timeout=50 if name == "timeout" else 5000,
                               bytes=2097152 if name == "size-large" else 64 if name == "size-small" else 1048576)
                result = R.parse_json(C.run(["--list-fetch"], G.json_text(payload).encode()))
                requests = [R.parse_json(r["body"]) for r in C.logged(log)]
                if name in {"size-small", "timeout"}: assert result.get("error") == "rpcTransport: HTTP transport failed", "list inherited limit " + name
                elif name == "info-failure":
                    assert result.get("error") == "rpcError: Core rejected the request" and len(requests) == 3, "list descriptor-info propagates"
                else:
                    assert "utxos" in result, "list composed success " + name
                    assert len(requests) == 8, "list composed complete requests " + name
                    if name == "derive-failure": assert requests[4]["params"] == [0, 9999999, []], "list failed derive continues empty"
                    if name == "dedup":
                        first = R.result(data["entries"][4])
                        assert [u["txid"] for u in result["utxos"]] == [u["txid"] for u in first], "list descriptor first-seen dedup"
                    if name == "precision":
                        assert result["utxos"][0]["amount_sats"] == Decimal(9007199254740993), "list exact amount above binary64 integer precision"
                        assert result["total_amount_sats"] == sum(u["amount_sats"] for u in result["utxos"]), "list exact large total"
        print("list synthetic " + name + ": passed", flush=True)


def wallet_halves():
    data = R.parse_json((HERE / "recordings/single-list.json").read_bytes())
    lists = [e for e in data["entries"] if e["rpc"]["method"] == "listunspent"]
    lists[1]["responses"] = copy.deepcopy(lists[0]["responses"])
    parent = APP / ".lake/list-halves"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); path = root / "synthetic.json"; path.write_text(G.json_text(data))
        with C.responder(path) as (base, log, _):
            wallet = HERE / "recordings/shared/frozenkrill-single.json"
            args = ["onchain-list-utxos", "--wallet-file", str(wallet), "--rpc-url", base + "/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway"]
            result = network.checked_run(EXE, args, stub_url=base, capture_output=True, timeout=30)
            assert result.returncode == 0 and result.stderr == b"", "list synthetic wallet success"
            actual = R.parse_json(result.stdout)["utxos"]
            expected = R.result(lists[0])
            assert [u["txid"] for u in actual] == [u["txid"] for u in expected] * 2, "list no cross-half dedup/order"
            assert len(C.logged(log)) == 10, "list wallet both halves request count"
    print("list synthetic wallet: no cross-half dedup; both independent descriptor invocations", flush=True)


def fifo():
    parent = APP / ".lake/list-fifo"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); path = root / "output.fifo"; os.mkfifo(path)
        row = matrix()[0]
        args, data, _, expected = plan(row, root)
        with C.responder(HERE / "recordings/multipath-create.json") as (base, _, _):
            reader = subprocess.Popen([sys.executable, "-B", "-c", "import sys; sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())", str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            writer = None
            try:
                args += ["--rpc-url", base + "/wallet/single", "--rpc-user", "lck", "--rpc-password", "lck-throwaway", "-o", str(path)]
                network.refuse_spawn(args, base)
                writer = subprocess.Popen([str(EXE), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, errors = reader.communicate(timeout=15)
                assert reader.returncode == 0 and errors == b"", "list FIFO reader status"
                assert output and not output.endswith(b"\n"), "list FIFO full bytes/no newline before EOF"
                assert not differences(exact_json(G.json_text(expected)), exact_json(output)), "list FIFO exact JSON"
                stdout, stderr = writer.communicate(timeout=15)
                assert writer.returncode == 0 and stdout == stderr == b"", "list FIFO writer completion"
            finally:
                for child in [reader, writer]:
                    if child is not None:
                        if child.poll() is None: child.kill()
                        child.communicate(timeout=5)
    print("list FIFO: complete JSON before EOF; writer and reader reaped", flush=True)


def address_controls():
    parent = APP / ".lake/list-addresses"; parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        root = Path(directory); path = root / "synthetic.json"
        entries = [dict(method="POST", path="/synthetic", rpc=dict(method="listunspent", params=[params]),
                        responses=[dict(status=200, json=dict(result=None, error=dict(code=-99, message="synthetic request control")))])
                   for params in [[2, 9, ["synthetic-one", "synthetic-two"]], [1, 9999999, []]]]
        path.write_text(json.dumps(dict(entries=entries)))
        for i, (address, bounds) in enumerate([(" , synthetic-one, synthetic-two , ,", ["--min-conf=+2", "--max-conf", "9"]), (" , , ", [])]):
            with C.responder(path) as (base, log, _):
                args = ["onchain-list-utxos", "--rpc-url", base + "/synthetic", "--addresses", address, *bounds]
                result = network.checked_run(EXE, args, stub_url=base, capture_output=True, timeout=10)
                assert result.returncode == 1 and result.stderr == b"rpcError: Core rejected the request\n", "list address bounds/default/empty request"
                assert R.parse_json(C.logged(log)[0]["body"])["params"] == entries[i]["rpc"]["params"][0], "list address bounds/order actual parameters"
                assert result.stdout == b"", "list synthetic address failure has no success output"
    for row in [matrix()[5], matrix()[15]]: one(row, cookie=True)
    with C.responder(HERE / "recordings/single-list.json") as (base, log, _):
        data = R.parse_json((HERE / "recordings/single-list.json").read_bytes())
        entry = next(e for e in data["entries"] if e["rpc"]["method"] == "listunspent")
        addresses = ",".join(entry["rpc"]["params"][0][2])
        args = ["onchain-list-utxos", "--rpc-url", base + "/wallet/single", "--addresses", addresses, "--min-conf", "0", "--rpc-user", "lck", "--rpc-password", "secret-password-sentinel"]
        result = network.checked_run(EXE, args, stub_url=base, capture_output=True, timeout=10)
        assert result.returncode == 1 and result.stdout == b"" and result.stderr == b"rpcHttp: HTTP 401\n", "list auth failure secret-free"
    print("list synthetic address-bound/default/empty failure controls: 2/2; wallet/address cookies: 2/2; auth refusal: 1/1", flush=True)


def main():
    args = sys.argv[1:]
    if args == ["schema"]: schemas(); return 0
    if args[:1] == ["lexical"]: lexical(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["positional"]: positional(args[1] if len(args) > 1 else None); return 0
    if args == ["split"]: print(C.run(["--list-injected"]), end=""); return 0
    if args == ["injected"]: print(C.run(["--list-injected"]), end=""); return 0
    if args[:1] == ["--capture-one"]:
        if not network.isolated(): raise ValueError("reference capture requires a fresh network namespace")
        row = next(r for r in matrix() if r["name"] == args[1])
        result = one(row, Path(args[2])); Path(args[3]).write_text(json.dumps(result, indent=2) + "\n"); return 0
    if args == ["--capture"]:
        if network.sandbox() or network.isolated(): raise ValueError("capture parent must enter a fresh namespace for each case")
        built = subprocess.run(BUILD, capture_output=True, timeout=1800)
        assert built.returncode == 0, "pinned reference build: " + built.stderr.decode()
        reference = Path(built.stdout.decode().strip()) / "bin/cyberkrill"
        parent = APP / ".lake/list-capture"; parent.mkdir(parents=True, exist_ok=True)
        captures = []
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            for row in matrix():
                record = Path(directory) / (row["name"] + ".json")
                status = network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), "--capture-one", row["name"], str(reference), str(record)], timeout=90)
                assert status == 0 and record.exists(), "reference capture must actually run: " + row["name"]
                captures.append(json.loads(record.read_text()))
        DEST.write_text(json.dumps(dict(upstream="https://github.com/douglaz/cyberkrill", revision=PIN, captures=captures), indent=2) + "\n")
        print(f"list reference captures: {len(captures)}/18"); return 0
    if not (network.sandbox() or network.isolated()):
        return network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), *args], timeout=180)
    if args[:1] == ["synthetic"]: synthetic(args[1] if len(args) > 1 else None); return 0
    if args[:1] == ["help"]: help_controls(args[1] if len(args) > 1 else None); return 0
    if args == ["split-cli"]: split_controls(); return 0
    if args == ["positional-replay"]: positional_replay(); return 0
    if args == ["failures"]: failures(); return 0
    if args == ["wallet-halves"]: wallet_halves(); return 0
    if args == ["fifo"]: fifo(); return 0
    if args == ["address-controls"]: address_controls(); return 0
    if args[:1] == ["replay"]:
        for row in matrix():
            if len(args) == 1 or args[1] == row["name"]: one(row)
        return 0
    assert args == [], "list test selector"
    schemas(); lexical(); positional(); help_controls(); split_controls(); positional_replay()
    print(C.run(["--list-injected"]), end="")
    captures = json.loads(DEST.read_text())
    assert captures["revision"] == PIN and len(captures["captures"]) == 18, "list reference inventory"
    for row, reference in zip(matrix(), captures["captures"]):
        observed = one(row)
        assert observed["name"] == reference["name"], "list capture identity"
        for key in ["stdout", "file_bytes"]:
            if observed[key]: assert not differences(exact_json(observed[key]), exact_json(reference[key])), "list pinned reference " + row["name"]
        print("list replay: " + row["name"], flush=True)
    failures(); synthetic(); wallet_halves(); fifo(); address_controls()
    print("list CLI replay: 18/18; original recordings: 8 cases/11 methods/69 selectors/75 replies/69 auth controls", flush=True)
    return 0


if __name__ == "__main__": sys.exit(main())
