#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Exercise fiat consumer regressions with the existing compiled-mutation runner."""
import hashlib
import importlib
import json
import sys
from cases import APP

M = importlib.import_module("price-mutations")
DEST = APP / "test/golden/fiat-onchain-mutation-record.json"


def mutations():
    app = "Cyberkrill/App.lean"
    fiat = "Cyberkrill/Fiat.lean"
    def probe(name): return ["python3","-B","test/fiat-onchain.py","--probe",name]
    rows = [
        ("conversion-wiring",app,'match convertFiat fiat price.currency price.price precision with',
         'match Except.ok (Bitcoin.Amount.ofSats 1) with',probe("create-fiat"),"fiat command success create-fiat"),
        ("output-whole-sat",app,'convertAmounts services (parsed.map (·.2)) .wholeSat',
         'convertAmounts services (parsed.map (·.2)) .floorSat',probe("create-at"),"fiat command success create-at"),
        ("maximum-floor-sat",app,'convertAmounts services #[parsed] .floorSat',
         'convertAmounts services #[parsed] .wholeSat',probe("move-floor"),"fiat command success move-floor"),
        ("currency-cache",app,'prices.find? (·.currency == fiat.currency)',
         '(none : Option PriceFeed.Price)',probe("create-normalized"),"fiat command cache requests create-normalized"),
        ("msat-before-sat",fiat,'let rounded := ((fiat.amount.div price).mul ⟨100000000000, 1⟩).round',
         'let raw := ((fiat.amount.div price).mul ⟨100000000000, 1⟩)\n  let rounded := raw.numerator / raw.denominator',
         probe("create-at"),"fiat command success create-at"),
    ]
    text = (APP/app).read_text()
    old = text.split('def convertAmounts',1)[1].split('\nprivate def outputsWith',1)[0]
    old = 'def convertAmounts'+old
    new = old.replace('let mut prices : Array PriceFeed.Price := #[]','let mut prices ← retainedPrices.get')
    new = new.replace('prices := prices.push price','prices := prices.push price\n        retainedPrices.set prices')
    new = 'initialize retainedPrices : IO.Ref (Array PriceFeed.Price) ← IO.mkRef #[]\n\n'+new
    rows.append(("invocation-cache-lifetime",app,old,new,probe("lifetime"),"fiat command cache requests create-fiat"))
    assert len(rows)==6, "fiat consumer mutation inventory"
    return rows


def fingerprints():
    paths = ["Cyberkrill/App.lean","Cyberkrill/Fiat.lean","Cyberkrill/PsbtCommands.lean","Cyberkrill/MoveUtxos.lean",
        "CyberkrillTests.lean","CyberkrillTests/FiatOnchain.lean","test/fiat-onchain.py","test/fiat-onchain-mutations.py",
        "test/price-mutations.py","test/fiat-onchain-provenance.json","test/capture-fiat-onchain-reference.py","test/http/fiat-onchain-reference.json","test/recordings/fiat-create.json","test/recordings/fiat-funded.json"]
    return {p:hashlib.sha256((APP/p).read_bytes()).hexdigest() for p in paths}


def verify():
    record = json.loads(DEST.read_bytes())
    assert record["source_sha256"]==fingerprints(), "stale fiat consumer evidence"
    assert len(record["checks"])==6, "fiat consumer detecting count"
    for check,row in zip(record["checks"],mutations()):
        assert [check[k] for k in ["property","file","replace","with_text","command","assertion"]]==list(row), "fiat consumer mutation identity"
        assert [check[k]["status"] for k in ["build","red","restore_build","green"]]==[0,1,0,0], "fiat consumer compiled/runtime/restored statuses"
        assert row[-1] in check["failure"] and "AssertionError:" in check["failure"], "fiat consumer intended assertion"
    assert all(record[k]["status"]==0 for k in ["initial_build","initial_green","restored_full"])
    print("fiat consumer mutations: 6/6 compiled runtime reds; restored builds and greens",flush=True)


if __name__ == "__main__":
    if sys.argv[1:]==["--verify"]: verify()
    else:
        assert not sys.argv[1:]
        M.DEST=DEST; M.mutations=mutations; M.fingerprints=fingerprints; M.verify=verify
        M.main(["python3","-B","test/fiat-onchain.py"])
