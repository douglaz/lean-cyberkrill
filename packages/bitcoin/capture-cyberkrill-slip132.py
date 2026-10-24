# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture a pure SLIP-132 conversion in a fresh clone and delete its workspace."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

PACKAGE = Path(__file__).resolve().parent
REVISION = "27cad1faba86260b06665a89f0af5134d23525c2"
LOGS = PACKAGE / ".lake/slip132-capture-checks"


def run(label, command, cwd, env):
    with (LOGS / f"{label}.stdout").open("wb") as out, (LOGS / f"{label}.stderr").open("wb") as err:
        result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
    print(f"{label}: EXIT={result.returncode}", flush=True)
    assert result.returncode == 0, f"{label} failed; see separate capture streams"
    return (LOGS / f"{label}.stdout").read_text()


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(signum, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    derived = json.loads((PACKAGE / "test-data/slip132-derived.json").read_text())
    inputs = [r["encoded"] for r in derived if r["prefix"] in ("ypub", "zpub", "upub", "vpub")]
    assert len(derived) == 72 and len(inputs) == 48
    assert os.environ.get("TMPDIR"), "set TMPDIR to a private temporary root"
    work = Path(tempfile.mkdtemp(prefix="cyberkrill-slip132-", dir=os.environ["TMPDIR"]))
    try:
        clone = work / "source"
        env = dict(os.environ, CARGO_HOME=str(work / "cargo-home"))
        run("clone", ["git", "clone", "https://github.com/douglaz/cyberkrill", str(clone)], work, env)
        run("checkout", ["git", "checkout", REVISION], clone, env)
        assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=clone).decode().strip() == REVISION
        assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=clone)
        source = clone / "cyberkrill-core/src/slip132.rs"
        original = source.read_text()
        assert original.endswith("}\n") and original.count("mod tests {") == 1
        test = '''
    // Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
    // Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
    #[test]
    fn capture_slip132() -> Result<()> {
        let inputs: Vec<String> = serde_json::from_str(r##"''' + json.dumps(inputs) + '''"##)?;
        for input in inputs {
            let output = parse_slip132_xpub(&input)?.to_string();
            println!("SLIP132_CAPTURE\\t{}", serde_json::json!({"input": input, "output": output}));
        }
        Ok(())
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
            "-p cyberkrill-core --no-default-features --features trezor -j 2 --lib slip132 "
            "-- --nocapture --test-threads=1"], clone, env)
        rows = [json.loads(line.split("SLIP132_CAPTURE\t", 1)[1])
                for line in output.splitlines() if "SLIP132_CAPTURE\t" in line]
        assert len(rows) == 48 and [r["input"] for r in rows] == inputs
        target = PACKAGE / "test-data/cyberkrill-slip132.json"
        target.write_text(json.dumps(rows, indent=2) + "\n")
        target.with_suffix(".json.provenance").write_text(
            "Producer: cyberkrill at 27cad1faba86260b06665a89f0af5134d23525c2, MIT OR Apache-2.0, taken under MIT.\n"
            "Source: https://github.com/douglaz/cyberkrill/blob/27cad1faba86260b06665a89f0af5134d23525c2/cyberkrill-core/src/slip132.rs\n"
            "Function: parse_slip132_xpub(s)?.to_string(), through a temporary pure test.\n"
            "Command: TMPDIR=\"${TMP_ROOT:?}\" systemd-run --user --scope --quiet -p MemoryMax=8G "
            "-p MemorySwapMax=0 -p OOMPolicy=continue -p TasksMax=4096 timeout 3600 "
            "python3 -I packages/bitcoin/capture-cyberkrill-slip132.py\n"
            "Inputs: BIP32 test vectors 1 and 2, bip-0032.mediawiki at "
            "130b8e0fa7f30fa45532f080b87b8db27a79e46e, BSD-2-Clause; see Bitcoin/LICENSE-bips.\n"
            "Input source: https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0032.mediawiki\n"
            "Changes: derived: version bytes swapped, converted back by cyberkrill.\n"
            "Order: each of the 12 public inputs, then ypub, zpub, upub, vpub.\n"
            "Output only; no upstream code or private key material copied.\n")
        print("cyberkrill SLIP-132 goldens: 48/48", flush=True)
    finally:
        # Only this exact newly created workspace is removed.
        shutil.rmtree(work)
        assert not work.exists()
        print("capture clone, cargo cache and temporary HOME removed; workspace absent", flush=True)


if __name__ == "__main__":
    main()
