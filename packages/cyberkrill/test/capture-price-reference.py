#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture only pure pinned Rust functions in a disposable offline checkout."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from cases import APP
from evidence import write_record
from network import run_owned

PIN = "27cad1faba86260b06665a89f0af5134d23525c2"
URL = "https://github.com/douglaz/cyberkrill"
C = importlib.import_module("price-cases")

CORE_TEST = r'''
#[cfg(test)]
mod phase9_pure_capture {
    use super::*;
    #[test]
    fn phase9_pure_capture() {
        let rows: Vec<Value> = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../pure-price-cases.json"))).unwrap();
        for row in rows {
            let id = row["id"].as_str().unwrap();
            let op = row["op"].as_str().unwrap();
            eprintln!("PURE_CASE_BEGIN {id}");
            let result: Option<Value> = match op {
                "parse" | "response" if op == "parse" || row.get("bytes").is_some() => {
                    let parser: fn(&str, &str) -> anyhow::Result<Option<f64>> = match row["source"].as_str().unwrap() {
                        "coingecko" => parse_coingecko_price, "coinbase" => parse_coinbase_price,
                        "blockchain.info" => parse_blockchain_info_price, "kraken" => parse_kraken_price,
                        "fedi" => parse_fedi_price, "cex.io" => parse_cex_io_price,
                        "bitstamp" => parse_bitstamp_price, "yadio" => parse_yadio_price,
                        "gemini" => parse_gemini_price, _ => unreachable!(),
                    };
                    let bytes: Vec<u8> = row.get("bytes").map(|v| v.as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect()).unwrap_or_default();
                    let body = if op == "response" { String::from_utf8_lossy(&bytes).into_owned() } else { row["body"].as_str().unwrap().to_string() };
                    Some(match parser(&body, row["currency"].as_str().unwrap_or("USD")) {
                        Ok(value) => serde_json::json!({"ok":value}),
                        Err(error) => serde_json::json!({"error":format!("{error:#}")}),
                    })
                },
                "convert" => Some(match fiat_amount_to_millisats(row["amount"].as_str().unwrap().parse().unwrap(), row["price"].as_str().unwrap().parse().unwrap()) {
                    Ok(value) => serde_json::json!({"ok":value}),
                    Err(error) => serde_json::json!({"error":format!("{error:#}")}),
                }),
                "median" => Some(serde_json::json!(median(row["values"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().parse().unwrap()).collect()))),
                "display" => {
                    let value:f64=row["value"].as_str().unwrap().parse().unwrap();
                    Some(serde_json::json!({"fixed":format!("{value:.2}"),"json":value}))
                },
                "aggregate" => {
                    let quotes = row["quotes"].as_array().unwrap().iter().map(|q| PriceQuote {
                        source: Box::leak(q["source"].as_str().unwrap().to_string().into_boxed_str()),
                        price_per_btc:q["price"].as_str().unwrap().parse().unwrap(),
                    }).collect();
                    Some(match aggregate_btc_price("USD".to_string(),quotes) {
                        Ok(value) => {
                            if row["capture_breadcrumb"].as_bool().unwrap_or(false) {
                                // Carry the actual aggregate bits to the CLI's pure
                                // breadcrumb function without another numeric parse.
                                let path = format!("{}/../{}.json", env!("CARGO_MANIFEST_DIR"), id.replace('/', "-"));
                                std::fs::write(path, serde_json::to_vec(&serde_json::json!({
                                    "bits":value.price_per_btc.to_bits(),
                                    "sources":value.sources.iter().map(|q| (q.source,q.price_per_btc.to_bits())).collect::<Vec<_>>()
                                })).unwrap()).unwrap();
                            }
                            serde_json::json!({"ok":value})
                        },
                        Err(error) => serde_json::json!({"error":format!("{error:#}")}),
                    })
                },
                _ => None,
            };
            if let Some(result) = result { println!("PURE_PRICE {}",serde_json::json!({"id":id,"result":result})); }
            eprintln!("PURE_CASE_END {id}");
        }
    }
}
'''

CLI_TEST = r'''
#[cfg(test)]
mod phase9_pure_capture {
    use super::*;
    #[test]
    fn phase9_pure_capture() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../pure-price-cases.json"))).unwrap();
        for row in rows {
            let id = row["id"].as_str().unwrap();
            let result = match row["op"].as_str().unwrap() {
                "cross-output" => {
                    let fiat=parse_fiat_amount(row["input"].as_str().unwrap()).unwrap();
                    // The legs also run through the core Fedi parser in the
                    // fedi/repeating case; the CLI constructor receives its ratio.
                    let price=cyberkrill_core::BtcPrice {currency:fiat.currency.clone(),
                        price_per_btc:row["btc_rate"].as_str().unwrap().parse::<f64>().unwrap()/row["fiat_rate"].as_str().unwrap().parse::<f64>().unwrap(),sources:vec![]};
                    let amount=convert_fiat_amount(&fiat,&price,FiatConversionPrecision::Millisat).unwrap();
                    serde_json::to_value(build_convert_amount_output(row["input"].as_str().unwrap(),&amount,Some(&(fiat,price)))).unwrap()
                },
                "aggregate" if row["capture_breadcrumb"].as_bool().unwrap_or(false) => {
                    let path = format!("{}/../{}.json", env!("CARGO_MANIFEST_DIR"), id.replace('/', "-"));
                    let captured:serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                    let price = cyberkrill_core::BtcPrice {currency:"USD".to_string(),
                        price_per_btc:f64::from_bits(captured["bits"].as_u64().unwrap()),
                        sources:captured["sources"].as_array().unwrap().iter().map(|q| cyberkrill_core::PriceQuote {
                            source:Box::leak(q[0].as_str().unwrap().to_string().into_boxed_str()),
                            price_per_btc:f64::from_bits(q[1].as_u64().unwrap()),
                        }).collect()};
                    eprintln!("PURE_CASE_BEGIN {id}");
                    emit_price_breadcrumb(&price);
                    eprintln!("PURE_CASE_END {id}");
                    continue;
                },
                "grammar" => match parse_fiat_amount(row["input"].as_str().unwrap()) {
                    Ok(value) => serde_json::json!({"ok":{"amount":value.amount,"currency":value.currency}}),
                    Err(error) => serde_json::json!({"error":format!("{error:#}")}),
                },
                "convert" => {
                    let fiat=FiatAmount {amount:row["amount"].as_str().unwrap().parse().unwrap(),currency:"USD".to_string()};
                    let price=cyberkrill_core::BtcPrice {currency:row["currency"].as_str().unwrap_or("USD").to_string(),price_per_btc:row["price"].as_str().unwrap().parse().unwrap(),sources:vec![]};
                    let mode=match row["mode"].as_str().unwrap() {"whole"=>FiatConversionPrecision::WholeSat,"floor"=>FiatConversionPrecision::FloorSat,_=>FiatConversionPrecision::Millisat};
                    match convert_fiat_amount(&fiat,&price,mode) {
                        Ok(amount)=>serde_json::json!({"ok":amount.as_millisats(),"output":build_convert_amount_output(id,&amount,Some(&(fiat,price)))}),
                        Err(error)=>serde_json::json!({"error":format!("{error:#}")}),
                    }
                },
                _ => continue,
            };
            println!("PURE_PRICE {}",serde_json::json!({"id":id,"result":result}));
        }
    }
}
'''


def main():
    destination = APP / "test/http/reference.json"
    logs = APP / ".lake/price-reference"
    logs.mkdir(parents=True, exist_ok=True)
    steps = []
    with tempfile.TemporaryDirectory(prefix="price-reference-", dir=os.environ["TMPDIR"]) as temporary:
        root = Path(temporary)
        clone, home = root / "reference", root / "home"
        home.mkdir()
        environment = dict(os.environ, HOME=str(home), TMPDIR=str(root), PYTHONDONTWRITEBYTECODE="1")
        def portable(text):
            text = text.replace(str(root), "$TMP_ROOT")
            text = re.sub(r"/nix[/]store/[^\s\"']+", "$NIX_STORE", text)
            text = re.sub(r"/(?:home|Users|root|tmp|var[/]tmp)/[^\s\"']+|/run[/]user/[^\s\"']+", "$LOCAL_PATH", text)
            return text
        def run(name, args, timeout, cwd=None):
            # run_owned owns and reaps the complete foreground process tree.
            from contextlib import chdir
            with chdir(cwd or root):
                result = run_owned(args, env=environment, capture_output=True, timeout=timeout)
            (logs / (name + ".stdout")).write_bytes(result.stdout)
            (logs / (name + ".stderr")).write_bytes(result.stderr)
            (logs / (name + ".status")).write_text(str(result.returncode) + "\n")
            step = dict(name=name, command=[portable(str(a)) for a in args], status=result.returncode,
                        stdout=portable(result.stdout.decode()), stderr=portable(result.stderr.decode()))
            steps.append(step)
            print(f"pure reference {name}: exit {result.returncode}", flush=True)
            return result.returncode == 0
        success = run("init", ["git", "init", "--quiet", str(clone)], 30)
        success = success and run("fetch", ["git", "fetch", "--quiet", "--depth=1", URL, PIN], 180, clone)
        success = success and run("checkout", ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], 30, clone)
        if success:
            rows = [{k:v for k,v in row.items() if k != "expected"} for row in C.pure_cases()]
            (clone / "pure-price-cases.json").write_text(json.dumps(rows))
            for path, test in [("cyberkrill-core/src/price_feed.rs", CORE_TEST), ("cyberkrill/src/main.rs", CLI_TEST)]:
                with (clone / path).open("a") as output: output.write(test)
            success = run("dependencies", ["nix", "develop", "-c", "env", "TMPDIR="+str(root), "cargo", "fetch", "--locked"], 1200, clone)
        if success:
            # The reference's own shell supplies its pinned compiler and libraries.
            # Only the named added pure tests execute; none opens a connection.
            for package in ["cyberkrill-core", "cyberkrill"]:
                success = run(package+"-features", ["nix", "develop", "-c", "env", "TMPDIR="+str(root),
                    "unshare", "-rn", "sh", "-c", 'ip link set lo up && exec cargo tree --offline --locked -p "$1" --no-default-features -e features -i serde_json',
                    "pure-reference", package], 120, clone)
                if not success: break
                success = run(package, ["nix", "develop", "-c", "env", "TMPDIR="+str(root),
                    "unshare", "-rn", "sh", "-c", 'ip link set lo up && exec cargo test --offline --locked -p "$1" --no-default-features phase9_pure_capture -- --nocapture --test-threads=1',
                    "pure-reference", package], 1800, clone)
                if not success: break
        bindings = {str(p.relative_to(APP)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [
            APP / "test/price-cases.py", APP / "test/http/success.json", Path(__file__).resolve()]}
        record = dict(reference=URL, revision=PIN, code_licence="MIT", source_sha256=bindings,
                      kind="pure Rust capture" if success else "prerequisite failure; expectations hand-derived", steps=steps)
        write_record(destination, json.dumps(record, indent=2) + "\n")
    return 0 if success else 1


if __name__ == "__main__": sys.exit(main())
