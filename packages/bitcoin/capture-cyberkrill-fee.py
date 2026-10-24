# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture only pure fee functions from a disposable, pinned upstream clone."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

PACKAGE = Path(__file__).resolve().parent
REVISION = "27cad1faba86260b06665a89f0af5134d23525c2"
LOGS = PACKAGE / ".lake/fee-capture-checks"
SHAPES = [(0, 0), (0, 1), (1, 0), (1, 1), (1, 2), (2, 2), (3, 1), (5, 1),
          (10, 1), (20, 1), (252, 1), (253, 1), (1, 252), (1, 253), (65535, 1), (65536, 1)]
RATES = ["0msat", "1msat", "1000msat", "1sat", "0.5sat", "0.1sat", "0.01sat", "1.15sats",
         "2.5sats", "15sats", "20sats", "100sats", "0.00000002", "0.00000002btc", "15",
         "9007199254740993msat", "18446744073709551615msat", "200000000btc"]
WEIGHTS = [0, 1, 3, 4, 5, 36028797018963972, 36028797018963980, 18446744073709551615]


def run(label, command, cwd, env):
    with (LOGS / f"{label}.stdout").open("wb") as out, (LOGS / f"{label}.stderr").open("wb") as err:
        result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
    print(f"{label}: EXIT={result.returncode}", flush=True)
    assert result.returncode == 0, f"{label} failed; see separate capture streams"
    return (LOGS / f"{label}.stdout").read_text()


def validate(data):
    expected = {"rates": 18, "shapes": 16, "shapeFees": 288, "weightFees": 144}
    for name, count in expected.items():
        assert len(data[name]) == count, (name, len(data[name]))
        print(f"fee {name}: {count}/{count}", flush=True)
    assert sum(map(len, data.values())) == 466
    assert [r["rate"] for r in data["rates"]] == RATES
    assert [(int(r["inputs"]), int(r["outputs"])) for r in data["shapes"]] == SHAPES
    assert [(int(r["inputs"]), int(r["outputs"]), r["rate"]) for r in data["shapeFees"]] == [
        (i, o, r) for i, o in SHAPES for r in RATES]
    assert [(int(r["weight"]), r["rate"]) for r in data["weightFees"]] == [
        (w, r) for w in WEIGHTS for r in RATES]
    parsed = {r["rate"]: int(r["msat"]) for r in data["rates"]}
    for r, n in {"1.15sats": 1150, "2.5sats": 2500, "0.5sat": 500, "0.01sat": 10,
                 "0.00000002": 2000, "0.00000002btc": 2000, "15": 1500000000000,
                 "18446744073709551615msat": 18446744073709551615,
                 "200000000btc": 18446744073709551615}.items():
        assert parsed[r] == n, (r, parsed[r], n)
    pins = [(40, 10), (164, 41), (314, 79), (438, 110), (562, 141), (834, 209),
            (982, 246), (1526, 382), (2886, 722), (5606, 1402), (68710, 17178),
            (68990, 17248), (31562, 7891), (31694, 7924), (17825694, 4456424), (17825974, 4456494)]
    assert [(int(r["weight"]), int(r["vbytes"])) for r in data["shapes"]] == pins
    fees = {(int(r["inputs"]), int(r["outputs"]), r["rate"]): int(r["sats"])
            for r in data["shapeFees"]}
    for rate, sats in [("1.15sats", 126), ("2.5sats", 275), ("0.1sat", 11), ("0.01sat", 1),
                       ("15", 165000000000), ("9007199254740993msat", 990791918021509),
                       ("200000000btc", 2029141848108050688)]:
        assert fees[1, 1, rate] == sats, (rate, fees[1, 1, rate], sats)
    assert fees[2, 2, "0.5sat"] == 105
    assert fees[253, 1, "18446744073709551615msat"] == 18446744073709551615
    direct = {(int(r["weight"]), r["rate"]): int(r["sats"]) for r in data["weightFees"]}
    for w, n in [(36028797018963972, 9007199254740992), (36028797018963980, 9007199254740996),
                 (18446744073709551615, 4611686018427387904)]:
        assert direct[w, "1sat"] == n
    print("fee total: 466/466; all reference pins matched", flush=True)


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    assert os.environ.get("TMPDIR"), "TMPDIR must be set"
    tmp = Path(os.environ["TMPDIR"]).resolve()
    assert tmp.is_dir(), "TMPDIR must name an existing directory"
    work = Path(tempfile.mkdtemp(prefix="cyberkrill-fee-", dir=tmp))
    try:
        clone = work / "source"
        env = dict(os.environ, CARGO_HOME=str(work / "cargo-home"))
        run("clone", ["git", "clone", "https://github.com/douglaz/cyberkrill", str(clone)], work, env)
        run("checkout", ["git", "checkout", REVISION], clone, env)
        assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=clone).decode().strip() == REVISION
        assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=clone)
        source = clone / "cyberkrill-core/src/bitcoin_rpc.rs"
        original = source.read_text()
        assert original.endswith("}\n") and original.count("mod tests {") == 1
        test = '''
    // Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
    // Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
    #[test]
    fn capture_fee() {
        let rates: Vec<String> = serde_json::from_str(r##"''' + json.dumps(RATES) + '''"##).unwrap();
        let shapes: Vec<(usize, usize)> = serde_json::from_str(r##"''' + json.dumps(SHAPES) + '''"##).unwrap();
        let weights: Vec<u64> = serde_json::from_str(r##"''' + json.dumps(WEIGHTS) + '''"##).unwrap();
        for rate in &rates {
            let amount = AmountInput::from_str(rate).unwrap();
            println!("FEE_CAPTURE\\t{}", serde_json::json!({"set":"rates", "rate":rate, "msat":amount.as_millisats().to_string()}));
        }
        for &(inputs, outputs) in &shapes {
            let w = BitcoinRpcClient::estimate_transaction_weight(inputs, outputs);
            println!("FEE_CAPTURE\\t{}", serde_json::json!({"set":"shapes", "inputs":inputs.to_string(), "outputs":outputs.to_string(), "weight":w.to_wu().to_string(), "vbytes":w.to_wu().div_ceil(4).to_string()}));
        }
        for &(inputs, outputs) in &shapes {
            let w = BitcoinRpcClient::estimate_transaction_weight(inputs, outputs);
            for rate in &rates {
                let a = AmountInput::from_str(rate).unwrap();
                let fee = BitcoinRpcClient::calculate_fee_with_feerate(w, a.as_fractional_sats());
                println!("FEE_CAPTURE\\t{}", serde_json::json!({"set":"shapeFees", "inputs":inputs.to_string(), "outputs":outputs.to_string(), "rate":rate, "sats":fee.to_sat().to_string()}));
            }
        }
        for weight in weights {
            for rate in &rates {
                let a = AmountInput::from_str(rate).unwrap();
                let fee = BitcoinRpcClient::calculate_fee_with_feerate(Weight::from_wu(weight), a.as_fractional_sats());
                println!("FEE_CAPTURE\\t{}", serde_json::json!({"set":"weightFees", "weight":weight.to_string(), "rate":rate, "sats":fee.to_sat().to_string()}));
            }
        }
    }
'''
        source.write_text(original[:-2] + test + "}\n")
        assert source.read_text() == original[:-2] + test + "}\n"
        run("fetch", ["nix", "develop", "-c", "bash", "-c",
                      "rustc --version && cargo --version && cargo fetch --locked"], clone, env)
        home = work / "home"
        home.mkdir()
        env["HOME"] = str(home)
        output = run("offline", ["nix", "develop", "-c", "unshare", "-rn", "sh", "-c",
            "ip link set lo up && cargo test --offline --locked --target x86_64-unknown-linux-gnu "
            "-p cyberkrill-core --no-default-features -j 2 --lib bitcoin_rpc::tests "
            "-- --nocapture --test-threads=1"], clone, env)
        data = {name: [] for name in ["rates", "shapes", "shapeFees", "weightFees"]}
        order = []
        for line in output.splitlines():
            if "FEE_CAPTURE\t" in line:
                row = json.loads(line.split("FEE_CAPTURE\t", 1)[1])
                name = row.pop("set")
                order.append(name)
                data[name].append(row)
        assert order == [n for n, c in [("rates", 18), ("shapes", 16), ("shapeFees", 288),
                                       ("weightFees", 144)] for _ in range(c)]
        validate(data)
        target = PACKAGE / "test-data/cyberkrill-fee.json"
        target.write_text(json.dumps(data, indent=2) + "\n")
        target.with_suffix(".json.provenance").write_text(
            f"Producer: cyberkrill at {REVISION}, MIT OR Apache-2.0, taken under MIT.\n"
            f"Source: https://github.com/douglaz/cyberkrill/blob/{REVISION}/cyberkrill-core/src/bitcoin_rpc.rs\n"
            "Functions: AmountInput::from_str, as_millisats, as_fractional_sats, "
            "estimate_transaction_weight, Weight::from_wu, calculate_fee_with_feerate, to_sat.\n"
            "Command: TMPDIR=\"${TMP_ROOT:?}\" systemd-run --user --scope --quiet -p MemoryMax=8G "
            "-p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 "
            "python3 -I packages/bitcoin/capture-cyberkrill-fee.py\n"
            "Inputs: our own synthetic inputs; captured output on our own synthetic inputs.\n"
            "Order: 18 rates, 16 shapes, 288 shape-major/rate-minor fees, 144 weight-major/rate-minor fees.\n"
            "All integer fields are decimal strings, preserving values above 2^53 exactly.\n"
            "Dependencies fetched online; tests offline under unshare -rn with temporary HOME.\n"
            "Output only; no upstream code copied.\n")
    finally:
        shutil.rmtree(work)
        assert not work.exists()
        print("capture clone, cargo cache and temporary HOME removed; workspace absent", flush=True)


if __name__ == "__main__":
    main()
