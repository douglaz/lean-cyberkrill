#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compare complete pure-reference values with narrow exact rational deltas."""
from copy import deepcopy
from decimal import Decimal
from fractions import Fraction
import hashlib
import json

from cases import APP
from compare import differences, exact_json


def rational(value):
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def numbers(value):
    if isinstance(value, (Decimal, int)) and not isinstance(value, bool): return Fraction(value)
    if isinstance(value, list): return [numbers(v) for v in value]
    if isinstance(value, dict): return {k:numbers(v) for k,v in value.items()}
    return value


def canonical(value):
    if isinstance(value, Fraction): return dict(number=str(value))
    if isinstance(value, list): return [canonical(v) for v in value]
    if isinstance(value, dict): return {k:canonical(v) for k,v in value.items()}
    return value


def observations(record, surface):
    step, = [s for s in record["steps"] if s["name"] == surface]
    assert step["status"] == 0, "pure reference execution status"
    output = []
    for line in step["stdout"].splitlines():
        if "PURE_PRICE " in line:
            output.append(exact_json(line.split("PURE_PRICE ",1)[1]))
    assert len(output) == len({r["id"] for r in output}), "unique pure reference identities"
    return {r["id"]:numbers(r["result"]) for r in output}


def deltas(rows, actual, *, record=None):
    if record is None:
        record = json.loads((APP / "test/http/reference.json").read_text())
    assert record["kind"] == "pure Rust capture" and record["revision"] == "27cad1faba86260b06665a89f0af5134d23525c2"
    for path, digest in record["source_sha256"].items():
        assert hashlib.sha256((APP/path).read_bytes()).hexdigest() == digest, "stale pure reference source: " + path
    core = observations(record, "cyberkrill-core")
    cli = observations(record, "cyberkrill")
    actual = {r["id"]:r["result"] for r in actual}
    found = []
    def compare(surface, case, reference, port, field="result"):
        # A success/refusal change pins the complete result and both identities.
        if isinstance(reference, dict) and isinstance(port, dict) and reference.keys() != port.keys():
            changed = [(field, reference, port)]
        else: changed = differences(reference, port, field)
        for path, r, p in changed:
            found.append(dict(surface=surface, case=case, field=path, reference=canonical(r), port=canonical(p)))
    for row in rows:
        name, op = row["id"], row["op"]
        value = actual[name]
        if op == "parse" or (op == "response" and "bytes" in row):
            ref = core[name]
            if "error" in value:
                if "error" in ref and ref["error"].split(": ",1)[0] == value["error"]:
                    continue
                compare("core", name, ref, value)
            else:
                compare("core", name, ref, dict(ok=None if value["ok"] is None else rational(value["ok"])))
        elif op == "grammar":
            ref = cli[name]
            if "error" in value:
                if "error" in ref:
                    assert value["error"].startswith("invalidFiat:"), name + " named exact grammar refusal"
                    assert ref["error"].startswith(("Invalid number in amount", "Invalid comma placement in amount",
                        "Unrecognized amount unit", "Cannot parse amount", "Bitcoin amount unit")), name + " reference grammar error context"
                else:
                    compare("cli", name, ref, value)
            else:
                compare("cli", name, ref, dict(ok=dict(amount=rational(value["ok"]["amount"]), currency=value["ok"]["currency"])))
        elif op == "convert":
            ref = cli[name]
            if "error" in value:
                if "error" in ref:
                    # Independently specified shared failures; require both named
                    # errors, not merely two objects containing an error key.
                    expected = {
                        "convert/tiny": ("Converted non-zero fiat amount is less than 1 msat", "Converted non-zero fiat amount is less than 1 msat"),
                        "convert/tiny-whole": ("Converted non-zero amount is less than 1 sat", "lessThanOneSat: Nonzero amount becomes less than one sat"),
                        "convert/tiny-floor": ("Converted non-zero amount is less than 1 sat", "lessThanOneSat: Nonzero amount becomes less than one sat"),
                        "convert/zero-price": ("Invalid BTC price for USD: 0", "Invalid BTC price"),
                        "convert/currency": ("BTC price currency mismatch: expected USD, got EUR", "BTC price currency mismatch: expected USD, got EUR"),
                    }
                    assert name in expected and (ref["error"], value["error"]) == expected[name], name + " conversion error identity/context"
                    continue
                compare("cli", name, ref, value)
            else:
                n = int(value["ok"])
                output = dict(input=name, btc=Fraction(n,10**11), sats=Fraction(n//1000), msats=Fraction(n),
                    fiat_source=dict(amount=Fraction(row["amount"]), currency=row.get("currency","USD"), price_per_btc=Fraction(row["price"]), feeds=[]))
                compare("cli", name, ref, dict(ok=Fraction(n),output=output))
        elif op == "median":
            compare("core", name, core[name], None if value is None else rational(value))
        elif op == "aggregate":
            ref = core[name]
            if "error" in value:
                assert ref == value, name + " reference quorum diagnostic"
                continue
            quotes = {q["source"]:Fraction(q["price"]) for q in row["quotes"]}
            port = dict(ok=dict(currency="USD",price_per_btc=rational(value["ok"]["price"]),
                sources=[dict(source=source,price_per_btc=quotes[source]) for source in value["ok"]["sources"]]))
            compare("core", name, ref, port)
            step, = [s for s in record["steps"] if s["name"] == "cyberkrill-core"]
            error = step["stderr"].split("PURE_CASE_BEGIN " + name + "\n",1)[1].split("PURE_CASE_END " + name,1)[0]
            compare("core", name, error, value["ok"]["warning"], "stderr")
            if row.get("capture_breadcrumb"):
                step, = [s for s in record["steps"] if s["name"] == "cyberkrill"]
                error = step["stderr"].split("PURE_CASE_BEGIN " + name + "\n",1)[1].split("PURE_CASE_END " + name,1)[0]
                compare("cli", name, error, value["ok"]["breadcrumb"], "stderr.breadcrumb")
        elif op == "display":
            compare("core", name, core[name], numbers(value))
        elif op == "cross-output":
            compare("cli", name, cli[name], numbers(value), "stdout")
    return found


def verify(rows, actual):
    observed = deltas(rows, actual)
    expected = json.loads((APP / "test/http/exact-deltas.json").read_text())
    assert observed == expected, "unlisted or unused exact price difference: " + repr(observed)
    # The required half-msat difference must be present and exercised.
    assert dict(surface="cli",case="convert/0.000010925",field='result["ok"]',
                reference=dict(number="11"),port=dict(number="12")) in observed
    assert len(observed) == 154, "exact price delta inventory"
    # The lexical cap is deliberately retained. Perturb each actual port result
    # and each captured reference result independently; neither change may hide
    # behind the named-error normalization or an unused allowlist entry.
    lexical = [row for row in rows if row["id"].startswith("bitstamp/lexical-")]
    assert len(lexical) == 8, "lexical comparator boundary inventory"
    for row in lexical:
        changed = deepcopy(actual)
        target, = [r for r in changed if r["id"] == row["id"]]
        target["result"] = dict(ok=dict(numerator="95001", denominator="1"))
        assert deltas(rows, changed) != expected, row["id"]+" altered port outcome detected"
        record = json.loads((APP / "test/http/reference.json").read_text())
        core, = [step for step in record["steps"] if step["name"] == "cyberkrill-core"]
        lines, matches = [], 0
        for line in core["stdout"].splitlines(keepends=True):
            if "PURE_PRICE " in line and json.loads(line.split("PURE_PRICE ",1)[1])["id"] == row["id"]:
                line = line.split("PURE_PRICE ",1)[0]+"PURE_PRICE "+json.dumps(dict(id=row["id"], result=dict(ok=95001)))+"\n"
                matches += 1
            lines.append(line)
        assert matches == 1, "lexical reference identity"
        core["stdout"] = "".join(lines)
        assert deltas(rows, actual, record=record) != expected, row["id"]+" altered reference outcome detected"
    print("lexical comparator: 8 altered port and 8 altered reference outcomes detected", flush=True)
    additions = __import__("price-cases").observed_price_cases()
    identities = {row["id"] for row in additions}
    assert len(additions) == 61 and len(identities) == 61, "observed comparator inventory"
    assert len([delta for delta in observed if delta["case"] in identities]) == 31, "observed exact delta additions"
    # Every newly captured complete outcome, including the finite neighbors,
    # is independently perturbed on both sides of the exact comparator.
    for row in additions:
        changed = deepcopy(actual)
        target, = [r for r in changed if r["id"] == row["id"]]
        target["result"] = dict(ok=dict(numerator="95001", denominator="1"))
        assert deltas(rows, changed) != expected, row["id"]+" altered port outcome detected"
        record = json.loads((APP / "test/http/reference.json").read_text())
        core, = [step for step in record["steps"] if step["name"] == "cyberkrill-core"]
        lines, matches = [], 0
        for line in core["stdout"].splitlines(keepends=True):
            if "PURE_PRICE " in line and json.loads(line.split("PURE_PRICE ",1)[1])["id"] == row["id"]:
                line = line.split("PURE_PRICE ",1)[0]+"PURE_PRICE "+json.dumps(dict(id=row["id"], result=dict(ok=95001)))+"\n"
                matches += 1
            lines.append(line)
        assert matches == 1, row["id"]+" captured reference identity"
        core["stdout"] = "".join(lines)
        assert deltas(rows, actual, record=record) != expected, row["id"]+" altered reference outcome detected"
    print(f"observed comparator: {len(additions)} altered port and {len(additions)} altered reference outcomes detected; 31 added deltas", flush=True)
    remaining = rows[487:]
    assert len(remaining) == 74, "remaining precision/path comparator inventory"
    identities = {row["id"] for row in remaining}
    assert len([d for d in observed if d["case"] in identities]) == 66, "remaining precision/path delta inventory"
    for row in remaining:
        changed = deepcopy(actual)
        target, = [r for r in changed if r["id"] == row["id"]]
        if row["op"] == "aggregate":
            target["result"]["ok"]["price"] = dict(numerator="95001", denominator="1")
        elif row["op"] == "grammar":
            target["result"] = dict(ok=dict(amount=dict(numerator="95001", denominator="1"), currency="USD"))
        else:
            target["result"] = dict(ok=dict(numerator="95001", denominator="1"))
        assert deltas(rows, changed) != expected, row["id"]+" altered port outcome detected"
        record = json.loads((APP / "test/http/reference.json").read_text())
        surface = "cyberkrill" if row["op"] == "grammar" else "cyberkrill-core"
        step, = [step for step in record["steps"] if step["name"] == surface]
        lines, matches = [], 0
        for line in step["stdout"].splitlines(keepends=True):
            if "PURE_PRICE " in line and json.loads(line.split("PURE_PRICE ",1)[1])["id"] == row["id"]:
                line = line.split("PURE_PRICE ",1)[0]+"PURE_PRICE "+json.dumps(dict(id=row["id"], result=dict(ok=95001)))+"\n"
                matches += 1
            lines.append(line)
        assert matches == 1, row["id"]+" captured reference identity"
        step["stdout"] = "".join(lines)
        assert deltas(rows, actual, record=record) != expected, row["id"]+" altered reference outcome detected"
        if row.get("capture_breadcrumb"):
            # Price and ordered quotes are compared separately from both streams.
            for surface, field in [("cyberkrill-core", "warning"), ("cyberkrill", "breadcrumb")]:
                record = json.loads((APP / "test/http/reference.json").read_text())
                step, = [s for s in record["steps"] if s["name"] == surface]
                marker = "PURE_CASE_BEGIN " + row["id"] + "\n"
                assert step["stderr"].count(marker) == 1
                step["stderr"] = step["stderr"].replace(marker, marker+"altered stream\n",1)
                assert deltas(rows, actual, record=record) != expected, row["id"]+" altered reference "+field
                changed = deepcopy(actual)
                target, = [r for r in changed if r["id"] == row["id"]]
                target["result"]["ok"][field] += "altered stream\n"
                assert deltas(rows, changed) != expected, row["id"]+" altered port "+field
    print("remaining comparator: 74 altered port and 74 altered reference outcomes detected; 66 added deltas; three separate warning/breadcrumb stream pairs", flush=True)
    print(f"pure Rust parity: {len(rows)} vectors; {len(observed)} narrow field/stream deltas exercised", flush=True)
