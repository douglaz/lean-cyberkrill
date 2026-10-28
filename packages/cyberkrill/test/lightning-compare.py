# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Only the settled Lightning differences, with exact case/field/stream pins."""
import copy
import json

from compare import Comparator, differences, exact_json

PAYEE = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
STRICT = {
    "negative/payment-hash-padding": "nonCanonicalPadding: tag=1",
    "negative/description-padding": "nonCanonicalPadding: tag=13",
    "negative/expiry-leading-zero": "leadingZero: tag=6",
    "negative/cltv-leading-zero": "leadingZero: tag=24",
    "negative/features-leading-zero": "leadingZero: tag=5",
    "negative/n-payment-hash-padding": "nonCanonicalPadding: tag=1",
}
URL_REFUSALS = {"url-refusal/" + name: "unsupportedUrlForm:" + reason for name, reason in [
    ("userinfo", "userinfo"), ("userinfo-multiple", "userinfo"), ("ipv6", "ipv6"),
    ("ipv4-hex", "ipv4Form"), ("ipv4-integer", "ipv4Form"), ("ipv4-short", "ipv4Form"),
    ("ipv4-octal", "ipv4Form"), ("ipv4-leading", "ipv4Form"), ("ipv4-dot", "ipv4Form"),
    ("unicode-host", "idnaRequired"), ("encoded-unicode-host", "idnaRequired"),
    ("punycode-host", "idnaRequired"), ("punycode-upper", "idnaRequired")
]}
URL_REFUSALS["url-error/scheme"] = "unsupportedScheme"
REFUSALS = {**STRICT, **URL_REFUSALS}
VALUE = "positive/amount-leading-zero"
STATUS = "positive/n-amount-leading-zero"


class LightningComparator:
    def __init__(self, rows):
        self.rows = {r["id"]: r for r in rows}
        assert len(self.rows) == len(rows), "Lightning capture identities"
        assert len(REFUSALS) == 20
        refusals = []
        for name, error in REFUSALS.items():
            ref = self.rows[name]["result"]
            assert ref["status"] == 0 and ref["stderr"] == "", "accepted reference refusal"
            refusals.append(dict(case=name, error=error, reference_status=0, port_status=1,
                reference_stdout=ref["stdout"], reference_stderr="",
                port_stderr=error + ": Invalid Lightning input\n"))
        self.inner = Comparator([dict(case=VALUE, field='stdout["destination"]', kind="string",
            reference="031b52bd31cb3ca5037014c137fb61ce7f05b32a690dc06bfffb6e490fcc610362", port=PAYEE)], refusals)
        self.status_used = False
        self.status_ref = dict(status=1, stdout="", stderr="Error: Failed to parse invoice: SemanticError(InvalidSignature)\n")
        assert self.rows[STATUS]["result"] == self.status_ref, "leading-zero reference verification pin"
        self.status_value = exact_json(self.rows["nfields/n-low"]["result"]["stdout"])
        assert self.status_value["destination"] == PAYEE

    def compare(self, row, ref, port):
        name = row["id"]
        if name == STATUS:
            assert ref == self.status_ref, "leading-zero reference status/streams"
            assert port["status"] == 0 and port["stderr"] == "", "leading-zero port status/stderr"
            assert not port["stdout"].endswith("\n"), "leading-zero stdout newline"
            assert not differences(self.status_value, exact_json(port["stdout"])), "leading-zero verified JSON"
            self.status_used = True
            return
        mode = "failure" if ref["status"] else "scalar" if row["args"][0] == "ln-encode-invoice" else "json"
        self.inner.compare(dict(id=name, mode=mode), ref, port)
        if port["status"] == 0:
            assert port["stdout"].endswith("\n") == (mode == "scalar"), "Lightning stdout newline: " + name

    def finish(self):
        self.inner.finish()
        assert self.status_used, "unused Lightning status exception"


def selftest(rows):
    baseline = LightningComparator(rows)
    expected = {r["id"]: copy.deepcopy(r["result"]) for r in rows}
    for name, code in REFUSALS.items():
        expected[name] = dict(status=1, stdout="", stderr=code + ": Invalid Lightning input\n")
    expected[VALUE]["stdout"] = json.dumps({**json.loads(expected[VALUE]["stdout"]), "destination": PAYEE})
    expected[STATUS] = dict(status=0, stdout=json.dumps(baseline.status_value, default=int), stderr="")
    exceptions = [*REFUSALS, VALUE, STATUS]
    assert len(exceptions) == 22
    rejected = 0
    for name in exceptions:
        row = baseline.rows[name]
        ref, port = row["result"], expected[name]
        LightningComparator(rows).compare(row, ref, port)
        changes = []
        for side in ["reference", "port"]:
            for stream in ["status", "stdout", "stderr"]:
                a, b = copy.deepcopy(ref), copy.deepcopy(port)
                target = a if side == "reference" else b
                target[stream] = (1 - target[stream]) if stream == "status" else target[stream] + "!"
                changes.append((a, b))
        if name in [VALUE, STATUS]:
            for field, value in [("destination", "wrong"), ("amount_msats", 123), ("extra", 1)]:
                changed = copy.deepcopy(port)
                changed["stdout"] = json.dumps({**json.loads(changed["stdout"]), field: value})
                changes.append((ref, changed))
        for a, b in changes:
            try:
                LightningComparator(rows).compare(row, a, b)
            except (AssertionError, ValueError):
                rejected += 1
            else:
                raise AssertionError("Lightning exception boundary accepted: " + name)
        try:
            LightningComparator(rows).compare({**row, "id": "unlisted/" + name}, ref, port)
        except (AssertionError, ValueError):
            rejected += 1
        else:
            raise AssertionError("unlisted Lightning exception accepted")
    try:
        LightningComparator(rows).finish()
    except AssertionError:
        rejected += 1
    else:
        raise AssertionError("unused Lightning exceptions accepted")
    assert rejected == 161
    print("Lightning exception boundaries: 161/161 rejected changes; 22/22 positive controls")
