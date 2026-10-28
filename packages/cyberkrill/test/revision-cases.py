# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Synthetic parser and IO regressions derived from published invoice captures."""
import copy
import json

ROOT_FIELDS = ["network", "amount_msats", "timestamp", "timestamp_millis", "payment_hash",
               "payment_secret", "features", "description", "description_hash", "destination",
               "expiry_seconds", "min_final_cltv_expiry", "fallback_addresses", "routes"]
HOP_FIELDS = ["src_node_id", "short_channel_id", "fees", "cltv_expiry_delta",
              "htlc_minimum_msat", "htlc_maximum_msat"]
FEE_FIELDS = ["base_msat", "proportional_millionths"]


def cases(original):
    by_id = {r["id"]: r for r in original}
    base = json.loads(by_id["valid/L410"]["result"]["stdout"])
    routed = json.loads(by_id["valid/L516"]["result"]["stdout"])
    rows = []

    def raw(name, payload, error="invalidInvoiceJson"):
        rows.append(dict(id=name, args=["ln-encode-invoice", "-", "-k", "{published_key}"],
                         input=payload, error=error, files={}, outputs=[]))

    def encode(name, value, error="invalidInvoiceJson"):
        raw(name, json.dumps(value, ensure_ascii=True), error)

    timestamps = [
        ("compact-zone", "2017-06-01T10:57:38+0000"),
        ("unpadded-date", "2017-6-1T10:57:38Z"),
        ("expanded-year", "+10000-01-01T00:00:00Z"),
        ("utc-underflow", "-262143-01-01T00:00:00+01:00"),
        ("utc-name", "2017-06-01T10:57:38UTC"),
        ("utc-name-case", "2017-06-01T10:57:38uTc"),
        ("zone-space", "2017-06-01T10:57:38 Z"),
        ("numeric-zone-space", "2017-06-01T10:57:38 +01:00"),
        ("unpadded-time", "2017-6-1T1:2:3Z"),
        ("zone-tab", "2017-06-01T10:57:38\tZ"),
        ("zone-nbsp", "2017-06-01T10:57:38\u00a0Z"),
        ("surrounding-space", " \t2017-06-01T10:57:38Z\u00a0\n"),
        ("component-space", "2017 - 6 - 1T 1 : 2 : 3Z"),
        ("component-unicode-space", "2017\u00a0-\t6 - 1T\t1\u00a0: 2 : 3Z"),
        ("upper-year", "+262142-01-01T00:00:00Z"),
        ("max-date", "+262142-12-31T23:59:59Z"),
        ("utc-overflow", "+262142-12-31T23:59:59-00:01"),
        ("utc-max-inward", "+262142-12-31T23:59:59+00:01"),
        ("min-date", "-262143-01-01T00:00:00Z"),
        ("utc-min-inward", "-262143-01-01T00:00:00-00:01"),
        ("utc-min-exact", "-262143-01-01T00:01:00+00:01"),
        ("utc-min-second", "-262143-01-01T00:00:59+00:01"),
        ("utc-max-exact", "+262142-12-31T23:58:59-00:01"),
        ("utc-max-second", "+262142-12-31T23:59:00-00:01"),
        ("negative-year", "-0001-01-01T00:00:00Z"),
        ("unsigned-short-year", "1-1-1T0:0:0Z"),
        ("signed-short-year", "+1-1-1T0:0:0Z"),
        ("signed-leading-zeros", "+000002017-1-1T0:0:0Z"),
        ("unsigned-expanded", "10000-01-01T00:00:00Z"),
        ("year-overflow", "+262143-01-01T00:00:00Z"),
        ("year-underflow", "-262144-12-31T23:59:59Z"),
        ("year-i64-overflow", "+9223372036854775808-01-01T00:00:00Z"),
        ("year-empty-sign", "+-01-01T00:00:00Z"),
        ("year-sign-space", "+ 2017-01-01T00:00:00Z"),
        ("fraction-long", "2017-06-01T10:57:38.123456789123Z"),
        ("fraction-empty", "2017-06-01T10:57:38.Z"),
        ("fraction-space", "2017-06-01T10:57:38 .1Z"),
        ("leap-second", "2017-06-01T10:57:60.9Z"),
        ("second-overflow", "2017-06-01T10:57:61Z"),
        ("lower-case", "2017-06-01t10:57:38z"),
        ("space-separator", "2017-06-01 10:57:38Z"),
        ("tab-separator", "2017-06-01\t10:57:38Z"),
        ("space-before-t", "2017-06-01 T10:57:38Z"),
        ("zone-colons", "2017-06-01T10:57:38+01:: 30"),
        ("zone-unicode-minus", "2017-06-01T10:57:38\u221201:30"),
        ("zone-hour-short", "2017-06-01T10:57:38+1:30"),
        ("zone-minute-short", "2017-06-01T10:57:38+01:3"),
        ("zone-hour-overflow", "2017-06-01T10:57:38+24:00"),
        ("zone-minute-overflow", "2017-06-01T10:57:38+01:60"),
        ("zone-no-minute", "2017-06-01T10:57:38+01"),
        ("zone-trailing", "2017-06-01T10:57:38UTCjunk"),
        ("date-leap-valid", "2000-02-29T00:00:00Z"),
        ("date-leap-invalid", "1900-02-29T00:00:00Z"),
        ("date-day-zero", "2017-06-00T00:00:00Z"),
        ("date-month-zero", "2017-00-01T00:00:00Z"),
        ("date-month-long", "2017-006-01T00:00:00Z"),
        ("hour-overflow", "2017-06-01T24:00:00Z"),
        ("minute-overflow", "2017-06-01T23:60:00Z"),
    ]
    for name, value in timestamps:
        encode("timestamp/" + name, {**base, "timestamp": value})

    for name, literal in [
        ("high", r'"\ud800"'), ("low", r'"\udc00"'),
        ("high-ascii", r'"\ud800\u0041"'), ("high-high", r'"\ud800\ud800"'),
        ("pair", r'"\ud83d\ude00"'), ("pair-upper", r'"\uD83D\uDE00"'),
        ("literal-backslash", r'"\\ud800"'), ("pair-then-low", r'"\ud83d\ude00\udc00"'),
    ]:
        payload = json.dumps({**base, "description": "__STRING__"})
        raw("unicode/known-" + name, payload.replace('"__STRING__"', literal))
        raw("unicode/ignored-" + name, json.dumps(base)[:-1] + ',"unused":' + literal + '}')
        raw("unicode/field-name-" + name, json.dumps(base)[:-1] + ',' + literal + ':null}')
        raw("unicode/nested-ignored-" + name, json.dumps(base)[:-1] + ',"unused":[' + literal + ']}')
    raw("unicode/ignored-nested-key-high", json.dumps(base)[:-1] + r',"unused":{"\ud800":1}}')
    raw("unicode/escaped-known-field", json.dumps(base).replace('"description"', r'"descriptio\u006e"'))

    root = [base[k] for k in ROOT_FIELDS]
    hop = [routed["routes"][0][0][k] for k in HOP_FIELDS]
    fees = [routed["routes"][0][0]["fees"][k] for k in FEE_FIELDS]
    for n in range(16):
        encode("sequence/root-length-" + str(n), root[:n] if n <= 14 else root + [None])
    for n in range(8):
        value = copy.deepcopy(routed)
        value["routes"][0][0] = hop[:n] if n <= 6 else hop + [None]
        encode("sequence/hop-length-" + str(n), value)
    for n in range(4):
        value = copy.deepcopy(routed)
        value["routes"][0][0]["fees"] = fees[:n] if n <= 2 else fees + [None]
        encode("sequence/fees-length-" + str(n), value)
    for name, values in [("root", root), ("hop", hop), ("fees", fees)]:
        for i in range(len(values)):
            value = copy.deepcopy(values); value[i] = None
            if name == "hop":
                payload = copy.deepcopy(routed); payload["routes"][0][0] = value
            elif name == "fees":
                payload = copy.deepcopy(routed); payload["routes"][0][0]["fees"] = value
            else: payload = value
            encode(f"sequence/{name}-null-{i}", payload)
    for root_array in [False, True]:
        for hop_array in [False, True]:
            value = copy.deepcopy(routed)
            value["routes"][0][0]["fees"] = fees
            if hop_array: value["routes"][0][0] = [value["routes"][0][0][k] for k in HOP_FIELDS]
            if root_array: value = [value[k] for k in ROOT_FIELDS]
            encode(f"sequence/combined-{int(root_array)}-{int(hop_array)}", value)
    for name, field, literal in [("unsigned", 1, "1e2"), ("millis", 3, "1.0"),
                                  ("timestamp", 2, '"bad"'), ("overflow", 10, str(2**64))]:
        value = copy.deepcopy(root); value[field] = "__LITERAL__"
        raw("sequence/root-" + name, json.dumps(value).replace('"__LITERAL__"', literal))
    for name, index, value in [("unsigned", 1, 1.0), ("delta-overflow", 3, 2**16),
                                ("minimum-overflow", 4, 2**64), ("key", 0, "zz")]:
        payload = copy.deepcopy(routed)
        h = copy.deepcopy(hop); h[index] = value; payload["routes"][0][0] = h
        encode("sequence/hop-" + name, payload, "badPublicKey" if name == "key" else "invalidInvoiceJson")
    for i in range(2):
        payload = copy.deepcopy(routed); f = fees[:]; f[i] = 2**32
        payload["routes"][0][0]["fees"] = f
        encode("sequence/fees-overflow-" + str(i), payload)
    from importlib import import_module
    forms = import_module("public-forms").forms
    for location, point in [("root", base["destination"]), ("hop", hop[0])]:
        for form in ["hybrid", "mismatched"]:
            value = forms(point)[form]
            if location == "root":
                payload = copy.deepcopy(root); payload[9] = value
            else:
                payload = copy.deepcopy(routed); h = copy.deepcopy(hop); h[0] = value
                payload["routes"][0][0] = h
            encode(f"sequence/{location}-{form}", payload, "badPublicKey")
    encode("simnet/encode", {**base, "network": "simnet",
                             "fallback_addresses": ["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"]})
    for command in ["ln-decode-invoice", "ln-decode-lnurl"]:
        for label, files, output in [("create", {}, "output.json"),
                                     ("truncate", {"output.json": "existing"}, "output.json"),
                                     ("open-error", {}, "."), ("missing-parent", {}, "absent/output.json")]:
            rows.append(dict(id="output/" + command + "-" + label,
                             args=[command, "bad", "-o", output], input=None,
                             error="outputFailure" if label in ["open-error", "missing-parent"] else "",
                             files=files, outputs=[output] if output != "." else []))
        rows.append(dict(id="output/" + command + "-read-before-open",
                         args=[command, "-o", "."], input_hex="ff", error="inputFailure", files={}, outputs=[]))
    for label, payload, files in [("create", "{", {}), ("preserve", "{", {"output.json": "existing"})]:
        rows.append(dict(id="output/encode-" + label,
                         args=["ln-encode-invoice", "-k", "{published_key}", "-o", "output.json"],
                         input=payload, error="invalidInvoiceJson", files=files, outputs=["output.json"]))
    assert len(rows) == len({r["id"] for r in rows})
    return rows


def decode_case(captured):
    value = next(r for r in captured if r["id"] == "simnet/encode")["result"]["stdout"].removesuffix("\n")
    return dict(id="simnet/decode", args=["ln-decode-invoice", value], input=None,
                error="", files={}, outputs=[])
