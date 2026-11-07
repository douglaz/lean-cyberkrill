#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Pinned pure conversion/cache parsing and Core result serialization; no handlers."""
import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
from cases import APP
from compare import exact_json
from evidence import write_record

DEST = APP / "test/http/fiat-onchain-reference.json"
PIN = "27cad1faba86260b06665a89f0af5134d23525c2"
R = importlib.import_module("rpc-recordings")

CORE_TEST = r'''
#[cfg(test)]
mod phase9_pure_capture {
    use super::*;
    #[test]
    fn phase9_pure_capture() {
        let rows:Vec<serde_json::Value>=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../pure-price-cases.json"))).unwrap();
        for row in rows.iter().filter(|r| r["op"]=="psbt-json") {
            assert_eq!(fiat_amount_to_millisats(95.04,95040.0).unwrap(),100000000);
            let psbt=row["psbt"].as_str().unwrap().to_string();
            let fee_sats=row["fee_sats"].as_u64().unwrap();
            let result=if row["funded"].as_bool().unwrap() {
                serde_json::to_value(crate::bitcoin_rpc::WalletFundedPsbtResponse {
                    psbt,fee_sats,change_position:row["change_position"].as_i64().unwrap().try_into().unwrap()
                }).unwrap()
            } else {
                serde_json::to_value(crate::bitcoin_rpc::PsbtResponse {psbt,fee_sats,change_position:None}).unwrap()
            };
            println!("PURE_PRICE {}",serde_json::json!({"id":row["id"],"result":result}));
        }
    }
}
'''

CLI_TEST = r'''
#[cfg(test)]
mod phase9_pure_capture {
    use super::*;
    #[tokio::test]
    async fn phase9_pure_capture() {
        let rows:Vec<serde_json::Value>=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../pure-price-cases.json"))).unwrap();
        for row in rows.iter().filter(|r| r["op"]!="psbt-json") {
            let mut cache=FiatPriceCache::default();
            for currency in ["USD","BRL","INR"] {
                cache.prices.insert(currency.to_string(),cyberkrill_core::BtcPrice {
                    currency:currency.to_string(),price_per_btc:row["price"].as_str().unwrap().parse().unwrap(),sources:vec![]
                });
            }
            let input=row["input"].as_str().unwrap();
            let result=if row["op"]=="outputs" {
                // Prove every possible fiat conversion is a cache hit BEFORE
                // entering the async parser. Never allow a fetch-capable miss.
                for entry in split_output_entries(input) {
                    if let ParsedAmount::Fiat(fiat)=parse_output_entry(entry).unwrap().amount {
                        assert!(cache.prices.contains_key(&fiat.currency));
                    }
                }
                let outputs=parse_outputs(input,&mut cache).await.unwrap();
                serde_json::json!(outputs.iter().map(|(address,amount)| (address,amount.to_sat())).collect::<Vec<_>>())
            } else {
                if let ParsedAmount::Fiat(fiat)=parse_amount(input).unwrap() {
                    assert!(cache.prices.contains_key(&fiat.currency));
                }
                let amount=parse_optional_btc_or_fiat_with_precision("--max-amount",Some(input),&mut cache,FiatConversionPrecision::FloorSat).await.unwrap().unwrap();
                serde_json::json!(amount.as_millisats()/1000)
            };
            println!("PURE_PRICE {}",serde_json::json!({"id":row["id"],"result":result}));
        }
    }
}
'''


def rows():
    values = [
        dict(id="outputs/recorded",op="outputs",input="a:95.04USD",price="95040",expected=[["a",100000]]),
        dict(id="outputs/mixed",op="outputs",input="a:95.04USD,b:1sat",price="95040",expected=[["a",100000],["b",1]]),
        dict(id="outputs/grouped",op="outputs",input="a:1,234USD,b:1,23,456INR",price="100000000",expected=[["a",1234],["b",123456]]),
        dict(id="outputs/normalized",op="outputs",input="a:1usd,b:2USD",price="100000000",expected=[["a",1],["b",2]]),
        dict(id="outputs/duplicates",op="outputs",input="a:1USD,a:2usd",price="100000000",expected=[["a",1],["a",2]]),
        dict(id="maximum/floor",op="maximum",input="1.75USD",price="100000000",expected=1),
        dict(id="maximum/zero",op="maximum",input="0USD",price="100000000",expected=0),
        dict(id="maximum/bitcoin",op="maximum",input="1.999sat",price="100000000",expected=1),
    ]
    for name in ["fiat-create","fiat-funded"]:
        data=R.parse_json((APP/"test/recordings"/(name+".json")).read_bytes())
        reply=R.result(data["entries"][-1]); funded=name=="fiat-funded"
        # Independent P2WPKH weight: four inputs, one output, explicit 1sat/vB.
        fee=int(reply["fee"]*100000000) if funded else (164+4*272+2+3)//4
        psbt=reply["psbt"] if funded else reply
        position=int(reply["changepos"]) if funded else None
        expected=dict(psbt=psbt,fee_sats=fee,change_position=position)
        values.append(dict(id="json/"+name,op="psbt-json",funded=funded,**expected,expected=expected))
    assert len(values)==10, "fiat pure reference input inventory"
    return values


def bindings():
    paths=[Path(__file__).resolve(),APP/"test/recordings/fiat-create.json",APP/"test/recordings/fiat-funded.json",APP/"test/http/success.json"]
    return {str(p.relative_to(APP)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def verify(record=None):
    if record is None: record=json.loads(DEST.read_bytes())
    assert record["revision"]==PIN and record["reference"]=="https://github.com/douglaz/cyberkrill" and record["code_licence"]=="MIT", "fiat pure reference authority"
    assert record["source_sha256"]==bindings(), "fiat pure reference bindings"
    if record["kind"]!="pure Rust capture":
        assert record["kind"]=="prerequisite failure; expectations hand-derived" and any(s["status"] for s in record["steps"]), "honest fiat reference build failure"
        print("fiat pure reference prerequisite failed; expectations remain hand-derived",flush=True)
        return
    assert all(s["status"]==0 for s in record["steps"]), "fiat pure reference command statuses"
    captured=[]
    for step in record["steps"]:
        for line in step["stdout"].splitlines():
            if "PURE_PRICE " in line: captured.append(exact_json(line.split("PURE_PRICE ",1)[1]))
    assert len(captured)==10 and len({r["id"] for r in captured})==10, "fiat pure reference captured inventory"
    expected={r["id"]:r["expected"] for r in rows()}
    assert {r["id"]:r["result"] for r in captured}==expected, "fiat complete pure reference values"
    print("fiat pure Rust reference: 10/10; seeded output/max parsers and complete Core result JSON",flush=True)


def capture():
    # Reuse the established foreground fetch/build/offline namespace producer.
    # Its historical output destination is intercepted; the fixed capture stays intact.
    source=importlib.import_module("capture-price-reference")
    original=APP/"test/http/reference.json"; before=original.read_bytes()
    inputs=[{k:v for k,v in row.items() if k!="expected"} for row in rows()]
    source.C=SimpleNamespace(pure_cases=lambda:inputs)
    source.CORE_TEST=CORE_TEST; source.CLI_TEST=CLI_TEST
    def publish(path,serialized):
        assert path==original, "reference producer destination contract"
        record=json.loads(serialized); record["source_sha256"]=bindings()
        verify(record)
        write_record(DEST,json.dumps(record,indent=2)+"\n")
    source.write_record=publish
    status=source.main()
    assert original.read_bytes()==before, "existing fixed price capture unchanged"
    return status


if __name__=="__main__":
    if sys.argv[1:]==["--verify"]: verify()
    else:
        assert not sys.argv[1:]
        sys.exit(capture())
