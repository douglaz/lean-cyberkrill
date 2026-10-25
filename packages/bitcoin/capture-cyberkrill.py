# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture only AmountInput::from_str, never the app or a network client.

Creates and retains an isolated clone, cargo cache and HOME under TMPDIR, which
must be set and name an existing directory.
Pass --clone only for a fresh clone of the pinned revision made for this run.
Dependencies are fetched online; the actual test builds and runs in unshare -rn.
Stdout and stderr are recorded separately under .lake/capture-checks.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


PACKAGE = Path(__file__).resolve().parent
REV = "27cad1faba86260b06665a89f0af5134d23525c2"


def run(label, command, cwd, env):
    logs = PACKAGE / ".lake/capture-checks"
    logs.mkdir(parents=True, exist_ok=True)
    with (logs / f"{label}.stdout").open("wb") as out, \
            (logs / f"{label}.stderr").open("wb") as err:
        result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
    print(json.dumps(dict(label=label, command=command, exit=result.returncode)), flush=True)
    stdout = (logs / f"{label}.stdout").read_text()
    stderr = (logs / f"{label}.stderr").read_text()
    if result.returncode:
        print(stdout, end="")
        print(stderr, end="")
        raise SystemExit(result.returncode)
    return stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clone", type=Path)
    args = parser.parse_args()
    assert os.environ.get("TMPDIR"), "TMPDIR must be set"
    tmp = Path(os.environ["TMPDIR"]).resolve()
    assert tmp.is_dir(), "TMPDIR must name an existing directory"
    work = Path(tempfile.mkdtemp(prefix="cyberkrill-amount-capture-", dir=tmp))
    clone = args.clone.resolve() if args.clone else work / "source"
    assert clone.is_relative_to(tmp), "clone must be isolated under TMPDIR"
    env = dict(os.environ, TMPDIR=str(tmp), CARGO_HOME=str(work / "cargo-home"))
    if not args.clone:
        run("clone", ["git", "clone", "https://github.com/douglaz/cyberkrill", str(clone)],
            work, env)
        run("checkout", ["git", "checkout", REV], clone, env)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=clone).decode().strip() == REV
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=clone), "fresh clone required"
    cases = json.loads((PACKAGE / "test-data/cli.json").read_text())
    inputs = json.dumps([dict(name=c["name"], input=c["input"]) for c in cases])
    test = clone / "cyberkrill-core/tests/amount_capture.rs"
    test.parent.mkdir(exist_ok=True)
    assert not test.exists()
    test.write_text('''// Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
// Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
use cyberkrill_core::bitcoin_rpc::AmountInput;
use std::str::FromStr;
#[test]
fn capture_amounts() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(r##"''' + inputs + '''"##).unwrap();
    for mut case in cases {
        let input = case["input"].as_str().unwrap();
        let value = AmountInput::from_str(input).ok().map(|a| a.as_millisats().to_string());
        case["msat"] = serde_json::to_value(value).unwrap();
        println!("AMOUNT_CAPTURE\\t{}", case);
    }
}
''')
    versions = run("fetch", ["nix", "develop", "-c", "bash", "-c",
                              "rustc --version && cargo --version && cargo fetch --locked"], clone, env)
    home = work / "home"
    home.mkdir()
    env["HOME"] = str(home)
    output = run("offline", ["nix", "develop", "-c", "unshare", "-rn", "sh", "-c",
        "ip link set lo up && cargo test --offline --locked --target x86_64-unknown-linux-gnu "
        "-p cyberkrill-core --no-default-features --test amount_capture -- --nocapture --test-threads=1"],
        clone, env)
    rows = [json.loads(line.split("AMOUNT_CAPTURE\t", 1)[1])
            for line in output.split("\n") if "AMOUNT_CAPTURE\t" in line]
    assert len(rows) == len(cases)
    assert [(r["name"], r["input"]) for r in rows] == [(c["name"], c["input"]) for c in cases]
    (PACKAGE / "test-data/cyberkrill-amounts.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(versions, end="")
    print(f"captured amounts: {len(rows)}/{len(cases)}; retained workspace: {work}")


if __name__ == "__main__":
    main()
