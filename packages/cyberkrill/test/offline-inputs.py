#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Read published inventories unchanged and construct deterministic CLI inputs."""
import base64
import copy
import importlib
import importlib.util
import json
import re

from cases import ROOT


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INV = load("invite_construction", ROOT / "packages/fedimint-invite/generate-fixtures.py")
WIRE = load("psbt_construction", ROOT / "packages/bitcoin/capture-cyberkrill-psbt.py")
COUNTS = dict(bip174Valid=10, bip174SignerFailures=4, bip174Roles=14, bip174Invalid=20,
              bip370Valid=14, bip370Invalid=24, bip370Locktimes=10, bip371Valid=6, bip371Invalid=11)


def published():
    source = (ROOT / "packages/bitcoin/Bitcoin/PsbtVectors.lean").read_text()
    rows = []
    for name, count in COUNTS.items():
        body = source.split("def " + name + " :", 1)[1].split("\n]", 1)[0]
        entries = re.findall(r'^  \(("(?:[^"\\]|\\.)*"), "([0-9a-f]+)", "([^"]*)"(?:, (none|some [0-9]+))?\)', body, re.M)
        assert len(entries) == count, "published inventory: " + name
        for index, (label, raw, text, locktime) in enumerate(entries):
            if not text:
                assert name == "bip174Roles" and index == 7, "only extracted transaction lacks Base64"
                text = base64.b64encode(bytes.fromhex(raw)).decode()
            assert bytes.fromhex(raw) == base64.b64decode(text, validate=True)
            row = dict(id=f"{name}/{index}", args=["onchain-decode-psbt", text],
                       source=f"BIP vectors: {name}, entry {index}", label=json.loads(label))
            if name in ["bip370Valid", "bip370Locktimes"]:
                groups = WIRE.maps(bytes.fromhex(raw))
                version = int.from_bytes(dict(groups[0]).get(b"\xfb", bytes(4)), "little")
                row["psbt_version"] = version
                if name == "bip370Locktimes":
                    row["locktime"] = None if locktime == "none" else int(locktime[5:])
            rows.append(row)
    assert len(rows) == 113
    assert sum(r.get("psbt_version") == 2 for r in rows if r["id"].startswith("bip370Valid/")) == 14
    return rows


def invites():
    rows = []

    def dec(name, text, source="synthetic original payload, constructed with the Phase 6 wrapper"):
        rows.append(dict(id="invite/" + name, args=["fm-decode-invite", text], source=source))

    def enc(name, value, skip=False):
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=True)
        rows.append(dict(id="invite-json/" + name, args=["fm-encode-invite", "-"] +
                         (["--skip-api-secret"] if skip else []), input=text,
                         source="synthetic JSON structure from the published invite shape"))

    primary = json.loads((ROOT / "packages/fedimint-invite/test-data/primary.json").read_bytes())
    assert len(primary) == 3
    for i, row in enumerate(primary):
        dec("primary-" + str(i), row["encoded"], "Phase 6 primary public invite " + str(i))
        enc("primary-" + str(i), row["decoded"])
        enc("primary-skip-" + str(i), row["decoded"], True)
    good = INV.parts(INV.guardian(2, "wss://example.com/"), INV.federation())
    ws = INV.parts(INV.guardian(0, "ws://example.com/"), INV.federation())
    for name, data in [
        ("truncated-no-url", b"\xfd"), ("truncated-wss", good[:23]),
        ("trailing", good + b"\xff\xff"),
        ("unknown", bytes([3]) + good[1:] + b"\x09\xff"),
        ("ws-trailing", ws + b"\xff"), ("ws-truncated", ws[:22]),
        ("http-consensus", INV.parts(INV.guardian(0, "http://example.com/"), INV.federation())),
        ("order", INV.parts(INV.guardian(2, "a"), INV.guardian(0, "b"), INV.guardian(2, "c"), INV.federation())),
        ("prefix-only", b"\xffwss://"), ("prefix-control", b"\xffwss://\x1f"),
        ("prefix-space", b"\xffwss:// "), ("https-six", b"\xffhttps:x"),
        ("http-fallback-reject", b"\xffhttp://x"), ("ws-fallback-reject", b"\xffws://x"),
        ("nested", b"\xffwss://awss://bhttps:c\0"),
        ("del-control", b"\xffwss://a\x7fwss://b\x80https:c\x00"),
        ("ascii31", b"\xffwss://a\x1fB"), ("ascii32", b"\xffwss://a B"),
        ("ascii126", b"\xffwss://a~B"), ("ascii127", b"\xffwss://a\x7fB"),
    ]:
        dec(name, INV.wrap(data))
    for size in [7, 8, 31, 32, 33, 63, 64, 65]:
        data = b"\xffwss://x" + bytes(range(max(0, size-8)))
        data = data[:size]
        assert len(data) == size
        dec("id-length-" + str(size), INV.wrap(data))
    text = INV.wrap(good)
    dec("uppercase", text.upper())
    dec("mixedcase", "F" + text[1:])
    dec("checksum", text[:-1] + ("q" if text[-1] != "q" else "p"))
    dec("wrong-hrp", INV.wrap(good, hrp="fed1x"))
    dec("wrong-variant", INV.wrap(good, variant=1))
    dec("unicode-trim", "\u0085\u2007" + text + "\u3000")
    dec("non-whitespace", "\u200b" + text)
    ds = INV.symbols(good)
    assert len(good)*8 % 5 != 0
    dec("lax-padding", INV.wrap(ds=ds[:-1]+[ds[-1] | 1]))
    dec("lax-extra-symbol", INV.wrap(ds=ds+[0]))
    basic = dict(federation_id="00"*32, guardians=[dict(peer_id=0, url="wss://example.com/")], api_secret=None)
    for field in basic:
        value = copy.deepcopy(basic); del value[field]; enc("missing-" + field, value)
        for name, replacement in [("null", None), ("object", {}), ("number", 1), ("bool", True)]:
            value = copy.deepcopy(basic); value[field] = replacement; enc(name+"-"+field, value)
    for field in ["peer_id", "url"]:
        value = copy.deepcopy(basic); del value["guardians"][0][field]; enc("missing-guardian-"+field, value)
    for i, peer in enumerate([0, 65535, 65536, -1, 1.5, "1", True, None]):
        value = copy.deepcopy(basic); value["guardians"][0]["peer_id"] = peer; enc("peer-"+str(i), value)
    peer_template = json.dumps(basic)
    assert peer_template.count('"peer_id": 0') == 1
    for name, literal in [("float", "0.0"), ("exponent", "0e0"), ("negative-zero", "-0"), ("positive", "+0"), ("underscore", "0_0")]:
        enc("peer-token-"+name, peer_template.replace('"peer_id": 0', '"peer_id": '+literal))
    for name, fid in [("empty", ""), ("short", "00"), ("odd", "0"), ("bad", "zz"*32), ("upper", "AB"*32)]:
        enc("id-"+name, {**basic, "federation_id": fid})
    enc("empty-guardians", {**basic, "guardians": []})
    enc("empty-url", {**basic, "guardians": [dict(peer_id=1, url="")]})
    enc("opaque-url", {**basic, "guardians": [dict(peer_id=1, url="opaque λ")]})
    enc("ordered-guardians", {**basic, "guardians": [dict(peer_id=2,url="a"),dict(peer_id=0,url="b")]})
    enc("struct-sequence", [basic["federation_id"], [[0, "hi"]], None])
    enc("short-sequence", [basic["federation_id"], [[0, "hi"]]])
    enc("long-sequence", [basic["federation_id"], [], None, None])
    enc("guardian-sequence", {**basic, "guardians": [[0,"hi"]]})
    enc("guardian-short", {**basic, "guardians": [[0]]})
    enc("duplicate-known", json.dumps(basic)[:-1] + ',"federation_id":""}')
    enc("duplicate-guardian", peer_template.replace('"peer_id": 0', '"peer_id": 0,"peer_id": 0'))
    enc("duplicate-unknown", json.dumps(basic)[:-1] + ',"unused":1,"unused":2}')
    enc("surrogate", peer_template.replace("wss://example.com/", "\\uD800"))
    enc("unknown-surrogate", json.dumps(basic)[:-1] + ',"unused":"\\uD800"}')
    enc("guardian-unknown-surrogate", peer_template.replace('"peer_id": 0', '"peer_id": 0,"unused":"\\uD800"'))
    enc("guardian-known-surrogate", peer_template.replace('"peer_id": 0', '"peer_id": 0,"url":"\\uD800"'))
    enc("skip-invalid-secret", {**basic,"api_secret": 3}, True)
    enc("malformed", "{")
    enc("trailing", json.dumps(basic)+" false")
    return rows


def psbts():
    rows = published()
    old = json.loads((ROOT / "packages/bitcoin/test-data/cyberkrill-psbt-capture.json").read_bytes())["rows"]
    assert len(old) == 49
    assert {name: sum(r["class"] == name for r in old) for name in ["must-reject","must-accept","port-stricter"]} == {
        "must-reject": 19, "must-accept": 14, "port-stricter": 16}
    rows += [dict(id="parity/"+r["name"], args=["onchain-decode-psbt",r["input_base64"]],
                  source="Phase 4a exact parity input: "+r["edit"], parity_class=r["class"]) for r in old]
    hybrids = importlib.import_module("hybrid-inputs").derive()
    rows += [dict(id=r["id"], args=["onchain-decode-psbt",r["input_base64"]],
                  source="synthetic public G/-G: hybrid-inputs.py", expected_success=r["expected_success"]) for r in hybrids]
    base = next(r for r in rows if r["id"] == "bip174Valid/0")
    for network in ["mainnet","bitcoin","testnet","signet","regtest","MAINNET","BITCOIN","TESTNET","SIGNET","REGTEST","MaInNeT"]:
        for identifier in ["bip174Valid/0","bip371Valid/0"]:
            value = next(r for r in rows if r["id"] == identifier)
            rows.append(dict(id=f"network/{identifier}/{network}", args=[*value["args"],"--network",network],source=value["source"]))
    rows.append(dict(id="psbt/hex",args=["onchain-decode-psbt",base64.b64decode(base["args"][1]).hex()],source=base["source"]))
    return rows


def synthetic_psbts():
    rows=[]
    def tx(value, script=b"", vout=0, version=2):
        return (version.to_bytes(4,"little")+b"\x01"+bytes(range(32))+vout.to_bytes(4,"little")+
                b"\0"+(123).to_bytes(4,"little")+b"\x01"+value.to_bytes(8,"little")+
                WIRE.compact(len(script))+script+(42).to_bytes(4,"little"))
    def add(name, value=3, records=(), script=b"", vout=0, version=2):
        raw=WIRE.encode([[(b"\0",tx(value,script,vout,version))],list(records),[]])
        rows.append(dict(id="synthetic-psbt/"+name,args=["onchain-decode-psbt",base64.b64encode(raw).decode()],
                         source="synthetic transaction and public script bytes; offline-inputs.py"))
    witness=lambda n: (b"\x01",n.to_bytes(8,"little")+b"\0")
    add("missing-value")
    add("witness",records=[witness(100000001)])
    add("nonwitness",records=[(b"\0",tx(200000003))])
    add("witness-precedence",records=[(b"\0",tx(200000003)),witness(100000001)])
    add("nonwitness-out-of-range",records=[(b"\0",tx(200000003))],vout=2)
    add("fee-saturates",value=100,records=[witness(1)])
    add("signed-version",version=2**32-1)
    add("large-exact",value=2**53+1,records=[witness(2**53+3)])
    add("max-output",value=2**64-1)
    for name,script in [("p2pkh",b"\x76\xa9\x14"+bytes(20)+b"\x88\xac"),
                        ("p2sh",b"\xa9\x14"+bytes(20)+b"\x87"),
                        ("p2wpkh",b"\0\x14"+bytes(20)),("p2wsh",b"\0\x20"+bytes(32)),
                        ("p2tr",b"\x51\x20"+bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
                        ("unsupported",b"\x6a")]:
        add(name,script=script)
        for network in ["testnet","signet","regtest"]:
            rows.append({**rows[-1],"id":f"synthetic-psbt/{name}-{network}",
                         "args":[*rows[-1]["args"][:2],"--network",network]})
    return rows


def routing_cases():
    rows=[]
    invite=json.loads((ROOT/"packages/fedimint-invite/test-data/primary.json").read_bytes())[0]
    psbt=published()[0]["args"][1]
    models=[("fm-decode-invite",invite["encoded"],None),
            ("fm-encode-invite","input=λ.json",json.dumps(invite["decoded"])),
            ("onchain-decode-psbt",psbt,None)]
    for command,value,payload in models:
        def add(name,args,**kwargs):
            row=dict(id="routing/"+command+"/"+name,args=[command,*args],source="synthetic argv/IO using published primary inputs")
            if payload is not None: row["files"]={value:payload}
            row.update(kwargs); rows.append(row)
        add("basic",[value])
        for i,args in enumerate([[value,"-o","out=λ"],[value,"--output=out=λ"],[value,"-oout=λ"],
                                 ["-oout=λ","--",value],[value,"-o=out=λ"],[value,"-o","-"]]):
            output="-" if i == 5 else "out=λ"
            add("output-"+str(i),args,observe=[output])
        add("overwrite",[value,"-o","out"],files={**({value:payload} if payload is not None else {}),"out":"old"},observe=["out"])
        for suffix in ["", "\n"]:
            add("stdin-"+str(len(suffix)),["-"] if payload is not None else [],input=(payload if payload is not None else value)+suffix)
        add("empty-stdin",["-"] if payload is not None else [],input="")
        add("extra",[value,"extra"])
        add("missing-output",[value,"-o"])
        add("output-option",[value,"-o","--help"])
        add("repeat-output",[value,"-o","a","--output","b"],observe=["a","b"])
        add("unknown",[value,"--unknown"])
        add("help",["--help"],help=True)
        add("literal-dash",["-"],input=(payload if payload is not None else value))
        add("output-error",[value,"-o","directory"],directories=["directory"],observe=["directory"])
        if command == "fm-decode-invite":
            for exists in [False,True]:
                add("invalid-output-"+str(exists),["invalid","-o","out"],files={"out":"old"} if exists else {},observe=["out"])
            add("invalid-open-error",["invalid","-o","directory"],directories=["directory"])
        elif command == "fm-encode-invite":
            add("absent",[])
            add("skip-repeat",[value,"--skip-api-secret","--skip-api-secret"])
            add("skip-attached",[value,"--skip-api-secret=false"])
            add("bad-json-preserve",["-","-o","out"],input="{",files={"out":"old"},observe=["out"])
            add("bad-json-no-create",["-","-o","out"],input="{",observe=["out"])
            add("read-before-open",["missing.json","-o","out"],observe=["out"])
            add("utf8-before-open",["invalid.json","-o","out"],file_hex={"invalid.json":"ff"},observe=["out"])
        else:
            add("existing-file",["input=λ.txt"],files={"input=λ.txt":value+"\n"})
            add("dash-file",["-"],files={"-":value})
            add("existing-directory",["directory","-o","out"],directories=["directory"],observe=["out"])
            add("utf8-before-open",["invalid.txt","-o","out"],file_hex={"invalid.txt":"ff"},observe=["out"])
            add("invalid-network",["directory","--network","bad","-o","out"],directories=["directory"],observe=["out"])
            add("network-attachment",[value,"--network=ReGtEsT"])
            add("network-repeat",[value,"--network=mainnet","--network=testnet"])
            add("network-missing",[value,"--network"])
            add("network-option",[value,"--network","--help"])
            add("bad-psbt-preserve",["invalid","-o","out"],files={"out":"old"},observe=["out"])
            add("bad-psbt-no-create",["invalid","-o","out"],observe=["out"])
    return rows


def ordered_help_cases():
    rows = []
    primary = json.loads((ROOT/"packages/fedimint-invite/test-data/primary.json").read_bytes())[0]
    for command in ["fm-decode-invite", "fm-encode-invite", "onchain-decode-psbt"]:
        variants = [
            ("help-unknown", ["--help", "--unknown"]),
            ("help-missing-output", ["--help", "-o"]),
            ("short-help-unknown", ["-h", "--unknown"]),
            ("unknown-help", ["--unknown", "--help"]),
            ("output-help", ["-o", "--help"]),
            ("help", ["--help"]),
            ("terminator-help", ["--", "--help"]),
            ("attached-output-help", ["-o--help", "--help"]),
            ("attached-output-data", ["-o--help", "--", "--help"]),
            ("long-output-data", ["--output=--help", "--", "--help"]),
            ("equals-output-data", ["-ox=--help", "--", "--help"]),
            ("filename-value-help", ["-o", "x=--help", "--help"]),
            ("repeat-output-help", ["-o", "a", "-o", "b", "--help"]),
            ("help-repeat-output", ["--help", "-o", "a", "-o", "b"]),
            ("extra-before-help", ["first", "second", "--help"]),
            ("help-extra", ["--help", "first", "second"]),
            ("output-terminator-help", ["-o", "--", "--help"]),
            ("empty-attached-help", ["--output=", "--help"]),
            ("help-output-error", ["--help", "-o", "directory"]),
            ("output-error-help", ["-o", "directory", "--help"]),
        ]
        if command == "onchain-decode-psbt":
            variants += [
                ("help-missing-network", ["--help", "--network"]),
                ("network-help", ["--network", "--help"]),
                ("invalid-network-help", ["--network=bad", "--help"]),
                ("repeat-network-help", ["--network=mainnet", "--network=testnet", "--help"]),
            ]
        if command == "fm-encode-invite":
            variants += [
                ("skip-value-help", ["--skip-api-secret=false", "--help"]),
                ("repeat-skip-help", ["--skip-api-secret", "--skip-api-secret", "--help"]),
                ("filename-help-data", ["--", "--help"]),
            ]
        for name, args in variants:
            row = dict(id=f"ordered-help/{command}/{name}", args=[command, *args],
                source="synthetic ordered argv using published invite JSON",
                files={"--help":json.dumps(primary["decoded"])}, directories=["directory"],
                observe=["--help", "x=--help", "a", "b", "directory"])
            # Measured with the pinned executable before selecting expectations.
            if name in {"help-unknown", "help-missing-output", "short-help-unknown", "help",
                        "attached-output-help", "filename-value-help", "help-repeat-output",
                        "help-extra", "empty-attached-help", "help-output-error", "output-error-help",
                        "help-missing-network", "invalid-network-help"}:
                row["help"] = True
            rows.append(row)
    assert len(rows) == 67, "ordered help construction count"
    return rows


def cluster_help_cases():
    primary = json.loads((ROOT/"packages/fedimint-invite/test-data/primary.json").read_bytes())[0]
    psbt = published()[0]["args"][1]
    rows = []
    for command in ["fm-decode-invite", "fm-encode-invite", "onchain-decode-psbt"]:
        content = psbt if command == "onchain-decode-psbt" else json.dumps(primary["decoded"])
        input_arg = primary["encoded"] if command == "fm-decode-invite" else "input.json"
        variants = [
            ("hx", ["-hx"]), ("hh", ["-hh"]), ("ho", ["-ho"]),
            ("ho-unknown", ["-ho", "--unknown"]),
            ("h-equals-one", ["-h=1"]), ("h-dashes", ["-h--unknown"]),
            ("hq-unknown", ["-hq", "--unknown"]), ("ho-value", ["-ho", "x"]),
            ("h-equals-x", ["-h=x"]), ("h-filename", ["-hinv.json"]),
            ("hx-long-help", ["-hx", "--help"]), ("repeat-cluster", ["-hh", "-hx"]),
            ("unknown-hh", ["--unknown", "-hh"]),
            ("unknown-short-hh", ["-x", "-hh"]),
            ("output-missing-cluster", ["-o", "-hx"]),
            ("terminator-cluster", ["--", "-hx"]),
            ("long-help-value", ["--help=x"]),
            ("invalid-long-cluster", ["--hx", "-hh"]),
            ("repeat-output-cluster", ["-o", "a", "-o", "b", "-hh"]),
            ("extra-before-cluster", ["first", "second", "-hh"]),
            ("output-short-h", [input_arg, "-oh"]),
            ("output-short-hyphen", [input_arg, "-o-hx"]),
            ("output-long-hyphen", [input_arg, "--output=-hx"]),
            ("output-short-equals", [input_arg, "-ox=-hx"]),
            ("output-utf8", [input_arg, "-o", "é=h"]),
            ("whitespace-value", ["-o", "h=é", input_arg]),
            ("filename", ["--", "-hx"]),
            ("output-cluster-help", ["-o-hx", "-hx"]),
            ("long-output-cluster-help", ["--output=-hx", "-hh"]),
            ("value-missing-then-help", ["-o", "-hx", "-hh"]),
            ("terminator-long-help", ["--", "-hx", "--help"]),
            ("prior-output-value", ["-o", "--help", "-hh"]),
        ]
        if command == "onchain-decode-psbt":
            variants += [
                ("network-value-cluster", ["--network", "-hx"]),
                ("repeat-network-cluster", ["--network=mainnet", "--network=testnet", "-hh"]),
                ("invalid-network-cluster", ["--network=bad", "-hh"]),
                ("network-missing-after-cluster", ["-hx", "--network"]),
            ]
        if command == "fm-encode-invite":
            variants += [
                ("repeat-skip-cluster", ["--skip-api-secret", "--skip-api-secret", "-hh"]),
                ("skip-value-cluster", ["--skip-api-secret=false", "-hh"]),
            ]
        for name, args in variants:
            rows.append(dict(id=f"cluster-help/{command}/{name}", args=[command, *args],
                source="synthetic short-help argv with published invite/PSBT inputs",
                files={"input.json":content, "-hx":content},
                observe=["input.json", "-hx", "h", "x=-hx", "é=h", "h=é", "a", "b", "--help"]))
            # Actual isolated reference successes, measured before pinning.
            if name in {"hx", "hh", "ho", "ho-unknown", "h-equals-one", "h-dashes",
                        "hq-unknown", "ho-value", "h-equals-x", "h-filename",
                        "hx-long-help", "repeat-cluster", "output-cluster-help",
                        "long-output-cluster-help", "invalid-network-cluster",
                        "network-missing-after-cluster"}:
                rows[-1]["help"] = True
    assert len(rows) == 102, "cluster help construction count"
    assert sum(bool(r.get("help")) for r in rows) == 44
    return rows


def carried_help_cases():
    variants = [
        ("enum-attached", "convert-amount", ["--as=x", "-hx"], False),
        ("enum-spaced", "convert-amount", ["--as", "x", "-hx"], False),
        ("enum-missing-terminator", "convert-amount", ["--as", "--", "-hx"], False),
        ("words-spaced", "generate-mnemonic", ["-w", "abc", "-hx"], False),
        ("words-equals", "generate-mnemonic", ["-w=abc", "-hx"], False),
        ("words-overflow", "generate-mnemonic", ["-w", "99999999999", "-hh"], False),
        ("words-missing-terminator", "generate-mnemonic", ["-w", "--", "-hx"], False),
        ("enum-empty", "convert-amount", ["--as=", "-hh"], False),
        ("enum-case", "convert-amount", ["--as=BTC", "-hh"], False),
        ("words-long-spaced", "generate-mnemonic", ["--words", "abc", "-hh"], False),
        ("words-long-attached", "generate-mnemonic", ["--words=abc", "-hh"], False),
        ("words-short-attached", "generate-mnemonic", ["-wabc", "-hh"], False),
        ("words-u32-overflow", "generate-mnemonic", ["-w", "4294967296", "-hx"], False),
        ("words-long-overflow", "generate-mnemonic", ["--words=4294967296", "-hx"], False),
        ("words-underscore", "generate-mnemonic", ["-w", "1_3", "-hx"], False),
        ("words-negative", "generate-mnemonic", ["-w=-1", "-hx"], False),
        ("words-empty", "generate-mnemonic", ["--words=", "-hx"], False),
        ("words-missing-help", "generate-mnemonic", ["--words", "-hh"], False),
        ("enum-help-first-attached", "convert-amount", ["-hx", "--as=x"], True),
        ("enum-help-first-spaced", "convert-amount", ["-hh", "--as", "x"], True),
        ("enum-help-first-missing", "convert-amount", ["-hx", "--as", "--"], True),
        ("words-help-first-grammar", "generate-mnemonic", ["-hx", "-w", "abc"], True),
        ("words-help-first-overflow", "generate-mnemonic", ["-hh", "--words=4294967296"], True),
        ("words-help-first-terminator", "generate-mnemonic", ["-hx", "-w", "--"], True),
        ("words-semantic-13", "generate-mnemonic", ["-w", "13", "-hx"], True),
        ("words-semantic-attached", "generate-mnemonic", ["-w13", "-hh"], True),
        ("words-semantic-plus", "generate-mnemonic", ["--words=+13", "-hx"], True),
        ("words-u32-max", "generate-mnemonic", ["--words=4294967295", "-hx"], True),
        ("enum-valid", "convert-amount", ["--as=sats", "-hx"], True),
        ("enum-runtime", "convert-amount", ["bad", "--as=btc", "-hh"], True),
        ("enum-long-help-first", "convert-amount", ["--help", "--as=x"], True),
        ("words-long-help-first", "generate-mnemonic", ["--help", "-w", "abc"], True),
    ]
    assert len(variants) == 32 and sum(v[3] for v in variants) == 14
    rows = []
    for name, command, args, help_result in variants:
        # No production invocation can request a valid mnemonic word count.
        # Only help, malformed u32 values and semantically impossible counts.
        if command == "generate-mnemonic":
            assert all(value not in args for value in ["12", "15", "18", "21", "24"])
            assert any("w" in token for token in args)
        row = dict(id="carried-help/"+name, args=[command, *args],
                   source="synthetic typed-flag/help precedence; no valid mnemonic count",
                   files={"dest":"unchanged\r\n"}, observe=["dest"])
        if help_result: row["help"] = True
        rows.append(row)
    return rows


def inventory():
    rows = invites() + psbts() + synthetic_psbts() + routing_cases() + ordered_help_cases() + cluster_help_cases() + carried_help_cases()
    assert len({r["id"] for r in rows}) == len(rows)
    return rows
