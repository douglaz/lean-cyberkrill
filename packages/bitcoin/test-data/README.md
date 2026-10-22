# Amount parser fixtures

`cli.json` contains 124 synthetic inputs and exact decimal expectations. Integers
are strings so no JSON reader can round them through binary floating point.
`delta` names an intentional rejection; `upstreamMsat` lists the four accepted
inputs whose exact value differs from the reference's floating-point result or
u64 saturation. No expected value comes from the Lean implementation.

`cyberkrill-amounts.json` is captured output on our own synthetic inputs from
[douglaz/cyberkrill](https://github.com/douglaz/cyberkrill/tree/27cad1faba86260b06665a89f0af5134d23525c2),
commit `27cad1faba86260b06665a89f0af5134d23525c2`,
`cyberkrill-core/src/bitcoin_rpc.rs`, `AmountInput::from_str` and
`AmountInput::as_millisats`. Upstream is MIT OR Apache-2.0, taken under MIT.
Only output is captured; no reference source code is copied here.

From the repository root:

```bash
python3 packages/bitcoin/capture-cyberkrill.py
```

The script retains its fresh clone and private cache in a temporary directory, adds one
pure parser test, fetches with that revision's `nix develop`, then builds and runs
only that test offline under `unshare -rn` with a throwaway HOME. The test never
constructs a client or opens a connection. Its stdout/stderr are captured
separately in `.lake/capture-checks/`. The committed JSON is the extracted test
output, with name/input columns checked against all 124 source rows.
