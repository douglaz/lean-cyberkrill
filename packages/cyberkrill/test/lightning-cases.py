# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Published BOLT11 and authored LNURL inventories and derived builder inputs."""
import copy
import importlib
import json

from cases import ROOT

# BOLT #11's published example key; no other signing key is used.
SPEC_KEY = "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734"
BOLT_COUNTS = dict(valid=16, invalid=15, negative=20, positive=4, nfields=2)
URL_COUNTS = {"url-supported": 35, "url-refusal": 13, "url-error": 23,
              "lnurl-positive": 8, "lnurl-negative": 12}


def inventory():
    bolt = json.loads((ROOT / "packages/lightning/test-data/bolt11.json").read_bytes())
    url = json.loads((ROOT / "packages/lightning/test-data/lnurl.json").read_bytes())
    reference = json.loads((ROOT / "packages/lightning/test-data/lnurl-reference.json").read_bytes())
    assert {k: len(bolt[k]) for k in BOLT_COUNTS} == BOLT_COUNTS
    assert {k: len(url[k]) for k in URL_COUNTS} == URL_COUNTS
    assert len(reference) == 1
    rows = []
    for group in BOLT_COUNTS:
        for row in bolt[group]:
            rows.append(dict(id=f"{group}/{row['name']}", args=["ln-decode-invoice", row["invoice"]],
                             spec=group in ["valid", "invalid"], source=row))
    for group in URL_COUNTS:
        for row in url[group]:
            rows.append(dict(id=f"{group}/{row['name']}", args=["ln-decode-lnurl", row["input"]], source=row))
    rows.append(dict(id="lnurl-reference/cyberkrill", args=["ln-decode-lnurl", reference[0]["input"]], source=reference[0]))
    assert len(rows) == 149 and len({r['id'] for r in rows}) == 149
    return rows


def builder_cases(captures):
    forms = importlib.import_module("public-forms").forms
    base = json.loads(next(r["result"]["stdout"] for r in captures if r["id"] == "valid/L410"))
    route = json.loads(next(r["result"]["stdout"] for r in captures if r["id"] == "valid/L516"))
    assert route["routes"] and route["routes"][0]
    result = []

    def add(name, value):
        result.append(dict(id="builder/" + name, args=["ln-encode-invoice", "-", "-k", "{published_key}"],
                           input=json.dumps(value, ensure_ascii=False)))

    for field, source in [("destination", base), ("route", route)]:
        point = source["destination"] if field == "destination" else source["routes"][0][0]["src_node_id"]
        for kind, value in forms(point).items():
            payload = copy.deepcopy(source)
            if field == "destination": payload[field] = value
            else: payload["routes"][0][0]["src_node_id"] = value
            add(field + "-" + kind, payload)
    for amount in [None, 0, 1, 99, 100, 99999, 100000, 100000000, 100000000000,
                   (2**64-1)//10, (2**64-1)//10+1, 2**64-1]:
        payload = copy.deepcopy(base)
        payload["amount_msats"] = amount
        add("amount-" + str(amount), payload)
    for network in ["bitcoin", "mainnet", "testnet", "regtest", "signet", "simnet"]:
        payload = copy.deepcopy(base); payload["network"] = network
        add("network-" + network, payload)
    for name, values in [
        ("empty-description", {"description": None, "description_hash": None}),
        ("description-first", {"description": "é coffee", "description_hash": base["payment_hash"]}),
        ("features-ignored", {"features": ["any_optional_bits", {"basic_mpp": "optional"}]}),
        ("empty-route", {"routes": [[], []]}),
        ("explicit-n-mismatch", {"destination": route["routes"][0][0]["src_node_id"]}),
        ("timestamp-max", {"timestamp_millis": (2**35-1)*1000}),
        ("timestamp-overflow", {"timestamp_millis": 2**35*1000}),
        ("timestamp-cast", {"timestamp_millis": 2**64*1000}),
    ]:
        payload = copy.deepcopy(base); payload.update(values); add(name, payload)
    assert len(result) == 34
    return result


def json_cases(captures):
    base = json.loads(next(r["result"]["stdout"] for r in captures if r["id"] == "valid/L410"))
    routed = json.loads(next(r["result"]["stdout"] for r in captures if r["id"] == "valid/L516"))
    result = []

    def raw(name, payload):
        result.append(dict(id="json/" + name, args=["ln-encode-invoice", "-", "-k", "{published_key}"], input=payload))

    def changed(name, field, value):
        payload = copy.deepcopy(base); payload[field] = value
        raw(name, json.dumps(payload, ensure_ascii=False))

    for field in base:
        payload = copy.deepcopy(base); del payload[field]
        raw("missing-" + field, json.dumps(payload))
        changed("null-" + field, field, None)
        changed("type-" + field, field, {})
    for field, bits in [("amount_msats", 64), ("timestamp_millis", 128),
                        ("expiry_seconds", 64), ("min_final_cltv_expiry", 64)]:
        for name, value in [("negative", -1), ("fraction", 1.5), ("string", "1"),
                            ("bool", True), ("overflow", 2**bits)]:
            changed(name + "-" + field, field, value)
        raw("float-" + field, json.dumps({**base, field: 1.0}))
        payload = json.dumps({**base, field: 123456789})
        assert payload.count("123456789") == 1
        raw("exponent-" + field, payload.replace("123456789", "1e2"))
    for field in ["payment_hash", "payment_secret", "description_hash", "destination"]:
        for name, value in [("hex", "zz"), ("odd", "0"), ("short", "00"), ("empty", "")]:
            changed(name + "-" + field, field, value)
    for i, value in enumerate([[], ["any_optional_bits"], [{"any_optional_bits": None}],
                              [{"basic_mpp": "required"}], [{"basic_mpp": {"optional": None}}],
                              ["basic_mpp"], [{"basic_mpp": "bad"}], [{"basic_mpp": None}],
                              [{"unknown": "optional"}], [{"basic_mpp": "optional", "payment_secret": "required"}]]):
        changed("feature-" + str(i), "features", value)
    for i, value in enumerate(["2017-06-01T10:57:38Z", "2017-06-01T10:57:38.123Z",
                              "2017-06-01T10:57:38.123456789Z", "2017-06-01t10:57:38z",
                              "2017-06-01 10:57:38+01:30", "2017-06-01T10:57:38+01:30",
                              "2017-02-30T10:57:38Z", "2017-06-01T24:00:00Z",
                              "2017-06-01T10:57:60Z", "2017-06-01T10:57:38", "bad"]):
        changed("timestamp-" + str(i), "timestamp", value)
    changed("network-object", "network", {"bitcoin": None})
    changed("network-upper", "network", "Bitcoin")
    for field, bits in [("short_channel_id", 64), ("cltv_expiry_delta", 16),
                        ("htlc_minimum_msat", 64), ("htlc_maximum_msat", 64)]:
        for name, value in [("overflow", 2**bits), ("type", "1")]:
            payload = copy.deepcopy(routed); payload["routes"][0][0][field] = value
            raw("hop-" + name + "-" + field, json.dumps(payload))
    for field in ["base_msat", "proportional_millionths"]:
        payload = copy.deepcopy(routed); payload["routes"][0][0]["fees"][field] = 2**32
        raw("fee-overflow-" + field, json.dumps(payload))
    for field in ["src_node_id", "short_channel_id", "fees", "cltv_expiry_delta"]:
        payload = copy.deepcopy(routed); del payload["routes"][0][0][field]
        raw("hop-missing-" + field, json.dumps(payload))
    for i, value in enumerate([[{}], [[{}]], "bad", [None]]):
        changed("route-shape-" + str(i), "routes", value)
    for i, value in enumerate([["bad"], [1], "bad"]):
        changed("fallback-" + str(i), "fallback_addresses", value)
    raw("unknown-fields", json.dumps({**base, "unused": {"unrelated": 1}}))
    raw("duplicate-known", json.dumps(base)[:-1] + ',"network":"bitcoin"}')
    raw("duplicate-unknown", json.dumps(base)[:-1] + ',"unused":1,"unused":2}')
    raw("malformed", "{")
    raw("trailing", json.dumps(base) + " false")
    for name, field, literal in [
        ("duplicate-network-enum", "network", '{"bitcoin":null,"bitcoin":null}'),
        ("duplicate-feature-enum", "features", '[{"basic_mpp":"optional","basic_mpp":"optional"}]'),
        ("duplicate-status-enum", "features", '[{"basic_mpp":{"optional":null,"optional":null}}]'),
        ("duplicate-unit-enum", "features", '[{"any_optional_bits":null,"any_optional_bits":null}]'),
    ]:
        payload = json.dumps({**base, field: "__ENUM_LITERAL__"})
        assert payload.count('"__ENUM_LITERAL__"') == 1
        raw(name, payload.replace('"__ENUM_LITERAL__"', literal))
    assert len(result) == 139
    return result


def routing_cases(captures):
    rows = {r["id"]: r for r in captures}
    cases = []
    for name in ["valid/L410", "lnurl-reference/cyberkrill"]:
        command, value = rows[name]["args"]
        for label, args, payload, files, outputs in [
            ("stdin", [command], value, {}, []),
            ("stdin-newline", [command], value + "\n", {}, []),
            ("literal-dash", [command, "-"], value, {}, []),
            ("file", [command, value, "-o", "output.json"], None, {}, ["output.json"]),
            ("attached-equals", [command, value, "-oout=name"], None, {}, ["out=name"]),
            ("overwrite", [command, value, "--output", "output.json"], None, {"output.json": "old"}, ["output.json"]),
        ]:
            cases.append(dict(id="routing/" + command + "-" + label, args=args, input=payload,
                              files=files, outputs=outputs))
    payload = rows["valid/L410"]["result"]["stdout"]
    utf8 = rows["builder/description-first"]["input"]
    for label, args, data, files, outputs in [
        ("stdin", [], payload, {}, []),
        ("dash-newline", ["-"], payload + "\n", {}, []),
        ("utf8-file", ["in=é.json"], None, {"in=é.json": utf8}, []),
        ("file", ["-", "-o", "invoice.txt"], payload, {}, ["invoice.txt"]),
        ("overwrite-equals", ["-", "-oinvoice=name"], payload, {"invoice=name": "old"}, ["invoice=name"]),
        ("terminator", ["--", "-in=é.json"], None, {"-in=é.json": payload}, []),
    ]:
        cases.append(dict(id="routing/ln-encode-invoice-" + label,
                          args=["ln-encode-invoice", "-k", "{published_key}", *args],
                          input=data, files=files, outputs=outputs))
    assert len(cases) == 18
    return cases
