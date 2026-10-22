# Phase 3b (1 of 2): four-data-error proof feasibility

## Verdict: stop

The complete certified literal-column check took **1198.049 s** with at most
four Lean processes, against the **600 s** finite-check wall-time limit.
All **220 files** passed: 219 chunks of 500 units and a final chunk of 236,
covering all **109,736** normalized tuples. Each file certifies its literal
table against the real `polymodStep`, then checks one chunk by binary
elimination over twenty columns with `decide +kernel`. No checker variants
were compared. The 12 GiB scope peaked at **6.2G** and exited **0**, with
no OOM message or timeout. Starting load was `19:46:50  up 388 days 22:53,  14 users,  load average: 18.37, 23.03, 15.72`.

This host stands in for the public Linux CI runner with four CPUs and 16 GB
RAM; the CI runner's per-core speed is unmeasured. The verdict concerns the
measured finite check on this host. The reduction, checker soundness, formal
coverage and assembly proofs remain unmeasured and are excluded from that
time, with no guessed allowance. The obstacle is the measured wall time above 600 s.

The full theorem remains unproved. Mathlib is unnecessary: structural list
induction, bit extensionality and binary elimination suffice in Lean core.
No package, dependency, flake input, library checker or soundness proof is
added. The exact target below is retained.

## The unchanged target

For each variant, as claimed by [BIP173, Checksum](https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0173.mediawiki#checksum)
and [BIP350](https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0350.mediawiki),
for a string valid under variant v (bech32 or bech32m) whose data part is at most
89 characters, any substitution of 1 to 4 data characters yields a string that
variant v's checksum verification rejects. Both sources are pinned to
bitcoin/bips commit `130b8e0fa7f30fa45532f080b87b8db27a79e46e`.

Data characters are **all characters after the separator, including the six
checksum characters**. Substitutions use the bech32 charset, preserving HRP
and separator position. With `Symbol := BitVec 5`, the intended Lean
statement over the existing definitions is:

```lean
def changes (d d' : List Symbol) : Nat :=
  (List.zipWith (fun x y => x != y) d d').count true

theorem detect_four (v : Variant) (h : String) (d d' : List Symbol)
    (len : d.length = d'.length)
    (minimum : 6 ≤ d.length) (maximum : d.length ≤ 89)
    (valid : verifyChecksum v h d = true)
    (positive : 1 ≤ changes d d') (small : changes d d' ≤ 4) :
    verifyChecksum v h d' = false
```

The corollary is over the real `decode`: if `s` decodes with variant `v` and
its data part has at most 89 characters (in particular any `s` accepted with
address limit 90), and `t` differs in 1 to 4 data positions, each replaced by a
charset character with the HRP and separator position unchanged, then
`decode limit t` does not return variant `v`, using the same limit.
Positions are counted by differences between the charset indices of
`Char.toLower t[i]` and `Char.toLower s[i]`; all other positions agree.
The count uses lowercase charset indices rather than raw character differences.

The length-90 dependency measured below does not change the target or supply
a fallback.
This spike does not cover cross-variant acceptance or witness-version rules.

## Reduction chain and proof obligations

All statements below other than `verifyChecksum_residue_eq` are proposed
proof obligations, **not checked theorems**. Definitions used to state the
obligations are directly over the existing `Symbol`, `polymodStep`, `polymod`,
`verifyChecksum`, `charOf`, `lower` and `decode`:

```lean
def L (e : List Symbol) : BitVec 30 :=
  (e.map (fun x => x.setWidth 30)).foldl polymodStep 0
def delta (d d' : List Symbol) : List Symbol := List.zipWith (· ^^^ ·) d d'
def weight (e : List Symbol) : Nat := (e.filter (· != 0)).length
def T (s : BitVec 30) : BitVec 30 := polymodStep s 0
def col (i : Nat) (x : Symbol) : BitVec 30 :=
  (List.replicate i (0 : BitVec 30)).foldl polymodStep (x.setWidth 30)
def columnSum (positions : List Nat) (coeffs : List Symbol) : BitVec 30 :=
  (List.zipWith col positions coeffs).foldl (· ^^^ ·) 0
def rendered (h : String) (d : List Symbol) : String :=
  h ++ "1" ++ String.ofList (d.map charOf)
```

1. **Decoder transport.** The proposed definitions below use the decoder's
   exact tail-first last-separator recursion and the real `lower` and `charOf`.
   The prefix is unchanged, including its case; only data charset indices
   count as edits. Wherever lowercase charset indices agree, the original
   characters agree exactly. Substitutions need not preserve letter case.

   ```lean
   -- The same tail-first recursion as the decoder's private splitLast.
   def dataParts : List Char → Option (List Char × List Char)
     | [] => none
     | c :: cs =>
       match dataParts cs with
       | some (h, d) => some (c :: h, d)
       | none => if c = '1' then some ([], cs) else none

   def dataLength (s : String) : Nat :=
     match dataParts s.toList with
     | none => 0
     | some (_, d) => d.length

   def DataEdits (s t : String) (k : Nat) : Prop :=
     ∃ h xs ys,
       dataParts s.toList = some (h, xs) ∧
       dataParts t.toList = some (h, ys) ∧
       xs.length = ys.length ∧
       (∀ c ∈ xs ++ ys, ∃ x : Symbol, c.toLower = charOf x) ∧
       (∀ p ∈ xs.zip ys, p.1.toLower = p.2.toLower → p.1 = p.2) ∧
       (List.zipWith (fun c c' => c != c')
         (lower (String.ofList xs)).toList
         (lower (String.ofList ys)).toList).count true = k
   ```

   The named transport obligation is:

   ```lean
   normalized_data_transport (hs : lower s = rendered h d)
     (ht : lower t = rendered h' d') (edits : DataEdits s t k) :
     h = h' ∧ d.length = d'.length ∧ changes d d' = k
   ```

   `decode_sound` supplies both decompositions and the two checksum verifications
   if both decodes return `v`. `chars_readChars`, `alphabet_inverse`,
   `alphabet_properties`, `splitLast_sound` and `splitLast_append` supply charset
   injectivity, lowercase stability and the last-separator decomposition. These
   helpers are currently private; a later proof would expose only the needed
   helpers without changing their statements. Charset symbols never equal the
   separator, so inserting them cannot move the last separator. The prefix
   lowercases identically in both strings. Each decoded data list here includes
   the six-symbol witness returned by `decode_sound`. It has length at least
   six. The supplied data-length bound gives at most 89. The final corollary is:

   ```lean
   decoder_detect_four (hs : decode limit s = .ok (h, payload, v))
     (edits : DataEdits s t k) (positive : 1 ≤ k) (small : k ≤ 4)
     (bound : dataLength s ≤ 89) :
     ∀ h' payload', decode limit t ≠ .ok (h', payload', v)
   ```

   Here `dataLength` is the suffix length after the real decoder's last
   separator. A failed decode already satisfies the conclusion; no acceptance
   assumption about `t` is added to the corollary. If `t` has mixed case,
   `decode` rejects it before checksum verification. Otherwise its lowercase
   decomposition supplies `ht` for `normalized_data_transport`; that obligation
   uses the shared prefix and lowercase charset injectivity, without a case
   preservation hypothesis.

2. **Acceptance to residue equality.** The delivered lemma is:

   ```lean
   theorem verifyChecksum_residue_eq (v : Variant) (hrp : String) (d d' : List Symbol)
       (valid : verifyChecksum v hrp d = true) (valid' : verifyChecksum v hrp d' = true) :
       polymod (hrpExpand hrp ++ d.map BitVec.toNat) =
         polymod (hrpExpand hrp ++ d'.map BitVec.toNat)
   ```

   It uses `beq_iff_eq` twice and transitivity through `v.constant`. It works
   for both variants and does not depend on the numeric value of their
   constants, generator constants, charset or HRP expansion. It is in
   `Bitcoin.Bech32Detection`, imported by `Bitcoin`. Existing definitions,
   theorem statements and visibility are unchanged. Its measured kernel cost
   is **0.312 ms**, from the profile command recorded below.

3. **Affine cancellation and error weight.** The obligations are:

   ```lean
   polymod_prefix_delta (p : List Nat) (len : d.length = d'.length) :
     polymod (p ++ d.map BitVec.toNat) ^^^ polymod (p ++ d'.map BitVec.toNat) =
       L (delta d d')
   delta_weight (len : d.length = d'.length) :
     (delta d d').length = d.length ∧ weight (delta d d') = changes d d'
   residue_delta_zero (len : d.length = d'.length)
     (eq : polymod (p ++ d.map BitVec.toNat) =
       polymod (p ++ d'.map BitVec.toNat)) : L (delta d d') = 0
   ```

   Use `List.foldl_append` to process the identical HRP prefix once, then the
   existing `fold_linear` and `fold_split` to cancel the shared initial state.
   Both are currently private and would need to be exposed for a separate
   module. Prove that widening a five-bit XOR commutes with XOR using bit
   extensionality. `x ^^^ y = 0 ↔ x = y` gives the weight assertion by list
   induction. The variant constant has already canceled, so both variants
   share exactly the same `L`.

4. **Columns, shifting, and four slots.** The column distance is measured from
   the end of the data, not its beginning. The obligations are:

   ```lean
   step_input (s : BitVec 30) (x : Symbol) :
     polymodStep s (x.setWidth 30) = T s ^^^ x.setWidth 30
   L_columns (e : List Symbol) :
     L e = columnSum ((List.range e.length).reverse) e
   T_injective : Function.Injective T
   trailing_zero_cancel (e : List Symbol) (k : Nat) :
     L (e ++ List.replicate k 0) = 0 ↔ L e = 0
   four_slots (bound : e.length ≤ 89)
     (positive : 1 ≤ weight e) (small : weight e ≤ 4) (zero : L e = 0) :
     ∃ a b c : Nat, 0 < a ∧ a < b ∧ b < c ∧ c < 89 ∧
       ∃ w : List Symbol, w.length = 4 ∧ 1 ≤ weight w ∧
         columnSum [0,a,b,c] w = 0
   ```

   `step_linear`, the direct identity `polymodStep 0 x = x`, and list induction
   prove the column expansion. Each symbol is an XOR of five single bits;
   `step_linear` propagates this decomposition through each distance.
   To prove `T_injective`, reduce to a zero kernel using linearity. The low
   five output bits determine the high five input bits; split those five
   Boolean bits and check the 32 cases using core simplification. Then the
   shifted remaining 25 bits must vanish. This is a symbolic bit proof over
   the real step, not an injectivity assumption.

   Strip leading zeros using `polymodStep 0 0 = 0` and trailing zeros using
   injectivity. Divide out the smallest nonzero distance, preserving a zero
   residue and nonzero coefficients. The remaining support contains distance
   zero and at most three other distances below 89. Extend this support to
   four distinct positions within `0..88`, assigning coefficient zero to any
   added positions. This covers weights **1, 2, 3 and 4**, including lengths
   smaller than four. No hypothesis is added to the target.

5. **Binary elimination and its soundness.** For a row list `rs`, define
   `xorMasked rs m` by structural recursion: for the head row, XOR it into
   the result exactly when `m % 2 = 1`, then recurse with `m / 2`. The checker's
   generic soundness obligation is:

   ```lean
   independent_sound (rs : List Nat) (ok : independent rs [] = true) :
     ∀ m : Nat, m < 2 ^ rs.length → xorMasked rs m = 0 → m = 0
   ```

   Prove the `insertRow` invariant: rows have strictly decreasing pivot
   `Nat.log2`; elimination preserves the XOR span; successful insertion adds
   a nonzero pivot outside the old span. In the equal-pivot branch, XOR
   reduces the pivot strictly. In the greater-pivot branch, inserting before
   the old row preserves the order. In the smaller-pivot branch, recurse
   into the tail and preserve the head. A zero residual means dependence.
   Induct over insertion, then over `independent`. This links `true` to
   independence, rather than trusting an unproved enumeration routine.

   The measured checker uses a literal `table` generated once per file,
   together with the kernel-checked certificate
   `table_real : table = columns 90`. `checkSets` reads that table, so no
   unit recomputes the real columns. The generator's arithmetic is not trusted:
   the certificate equates every literal row to the real `polymodStep` columns.
   Rewrite by `table_real` in checker soundness before using these representation
   obligations:

   ```lean
   columns_length (n : Nat) : (columns n).length = n
   columns_entry (i j : Nat) (hi : i < 90) (hj : j < 5) :
     ((columns 90)[i]!).getD j 0 = (col i (BitVec.ofNat 5 (2^j))).toNat
   col_bits (i : Nat) (x : Symbol) :
     col i x = ((List.range 5).map (fun j =>
       if x.getLsbD j then col i (BitVec.ofNat 5 (2^j)) else 0)).foldl (· ^^^ ·) 0
   ```

   Prove every row is below `2^30`,
   and use `BitVec.toNat`'s XOR identity and injectivity to transport zero
   XORs between Nat rows and the real thirty-bit residues. Concatenating four
   five-row blocks corresponds to the twenty coefficient bits of four
   `Symbol`s. Consequently:

   ```lean
   checkSets_sound (ok : checkSets sets = true)
     (member : (a,b,c) ∈ sets) (bounds : 0 < a ∧ a < b ∧ b < c ∧ c < 90)
     (w : List Symbol) (len : w.length = 4)
     (zero : columnSum [0,a,b,c] w = 0) : weight w = 0
   ```

   This uses the standard `List.all` characterization and `independent_sound`.
   Structural recursion and Nat bit operations allow ordinary kernel
   reduction with `decide +kernel`. Neither `native_decide` nor `bv_decide`
   is needed: the kernel reduces the structural functions and Nat literals
   itself, without `Lean.ofReduceBool`. Mathlib is unnecessary.
   The soundness proof remains unmeasured and undelivered.

6. **Exhaustiveness and the final finite fact.** Use 220 files, with one chunk
   theorem of at most 500 units per file, rather than one kernel reduction
   over the entire enumeration. Each file contains the same table certificate
   and the same checker definitions as the measured files. There are 219 full
   chunks and a last chunk of 236 units; no shared module is used. The three nested structural ranges
   enumerate exactly `0 < a < b < c < 89`. Required assembly and coverage
   statements are:

   ```lean
   def triples (n : Nat) : List (Nat × Nat × Nat) :=
     (List.range n).flatMap fun c =>
       (List.range c).flatMap fun b =>
         (List.range b).filterMap fun a =>
           if 0 < a then some (a,b,c) else none

   def chunks : List (List (Nat × Nat × Nat)) :=
     (List.range 220).map fun i => ((triples 89).drop (500 * i)).take 500

   checkSets_append (xs ys : List (Nat × Nat × Nat)) :
     checkSets (xs ++ ys) = (checkSets xs && checkSets ys)
   chunks_cover : chunks.flatten = triples 89
   chunks_checked : ∀ xs ∈ chunks, checkSets xs = true
   all_checked : checkSets (triples 89) = true
   ```

   `all_checked` is an assembly proof using `chunks_cover`, `chunks_checked`
   and `checkSets_append`, not a single full-size `decide +kernel`.
   Each generated literal sample must also be certified equal to its specified
   `drop`/`take` chunk; that coverage proof is unmeasured and excluded from the
   measured finite-check wall time. Table and literal-list identity certificates must be carried
   across module boundaries when assembling the chunks. The enumeration's
   completeness statement is:

   ```lean
   triples_complete (ha : 0 < a) (hab : a < b) (hbc : b < c) (hc : c < 89) :
     (a,b,c) ∈ triples 89
   ```

   Prove this by range membership and `filterMap`/`flatMap` membership. Combine
   it with `four_slots` and `checkSets_sound` to establish the precise finite
   fact, still over the real `L`:

   ```lean
   finite_no_four_kernel : ∀ e : List Symbol,
     e.length ≤ 89 → 1 ≤ weight e → weight e ≤ 4 → L e ≠ 0
   ```

   Finally, assuming the edited checksum is true, the delivered residue lemma,
   affine cancellation and `delta_weight` yield a nonzero weight-1-to-4 error
   with zero `L`, contradicting this fact. Boolean case analysis gives the
   requested `false`, and step 1 gives the decoder corollary.

The remaining reduction, checker-soundness, exhaustiveness, table-index and
chunk-assembly proofs are unmeasured. Their cost is excluded from the measured
finite-check wall time, with no numerical allowance added.

## Measured split run

Measured on 2026-10-22. `lscpu` exited **0**: AMD Ryzen 7 7700 8-Core
Processor, eight cores, two threads per core. `nproc` immediately before
the full scope exited **0**, printing **16**. `systemd-run --version`
exited **0**, reporting systemd **260 (260.5)**. The package environment
uses Lean **4.35.0**; the final validation records its version command.
No CPU affinity was set. Only the existing checker was measured here.

The generator writes self-contained files, each importing `Bitcoin.Bech32`,
with definitions, a literal table, the kernel certificate
`table_real : table = columns 90`, a literal sample, one chunk theorem and
`#print axioms checked`. There is no shared scratch module or shared-module
compilation. Table certification is paid once per file inside the measurement.

### Coverage and its failure check

`python3 "$TMP_ROOT/generate.py"` exited **0**:

```text
generated 220 chunks; 109736 units; size 500; final 236
manifest SHA-256: 961e781a7b867edac294803ce12f9d15e5a11b88179085513426ebb5200dac71
```

`python3 "$TMP_ROOT/coverage.py" "$TMP_ROOT"`, with streams captured
as `coverage.stdout` and `coverage.stderr`, exited **0**:

```text
PASS: 220 chunks; 109736 units; exact triples 89 order; no gaps, duplicates or extras
```

This reads the literal samples from the written files in index order.
Independently of the generator's nested loops, it sorts three-element
combinations by `(c,b,a)` and compares the whole sequence. Removing the
first tuple from a copy of `chunk000.lean` gives
`python3 "$TMP_ROOT/coverage.py" "$TMP_ROOT/coverage-red"`, exit **1**:

```text
FAIL: count=109735; duplicates=0; missing=1; extra=0
first missing: (1, 2, 3)
```

Both stderr files are empty. The original chunk files were unchanged.
The manifest `chunks.sha256` lists every chunk's SHA-256 using relative
names; its SHA-256 is **`961e781a7b867edac294803ce12f9d15e5a11b88179085513426ebb5200dac71`**. The exact
generator below reproduces that manifest and every chunk byte for byte.
The post-measurement command
`(cd "$TMP_ROOT" && sha256sum -c chunks.sha256)` exited **0** on all 220 files.

### Sequential pilots and sizing

Every row below ran separately in an 8 GiB foreground scope, with
`MemorySwapMax=0`, `OOMPolicy=continue` and `timeout 3600`. Wall time includes
the scope invocation and its supervision. Chunk kernel is the final
`type checking took` line; cumulative kernel is the profiler's cumulative
`type checking` line. Journal peaks retain the printed precision.

| Label / file | Units | Chunk kernel s | Cumulative kernel s | Wall s | Peak | Exit | Starting uptime |
|---|---:|---:|---:|---:|---|---:|---|
| `pilot-start` / `chunk000.lean` | 500 | 6.84 | 8.82 | 12.124 | 1.2G | 0 | 19:44:46  up 388 days 22:51,  14 users,  load average: 40.02, 24.83, 15.05 |
| `pilot-middle` / `chunk110.lean` | 500 | 16 | 17.7 | 20.374 | 1.7G | 0 | 19:45:05  up 388 days 22:51,  14 users,  load average: 38.31, 25.44, 15.46 |
| `pilot-heavy` / `chunk218.lean` | 500 | 15.4 | 17.6 | 20.095 | 1.9G | 0 | 19:45:26  up 388 days 22:51,  14 users,  load average: 36.52, 25.85, 15.81 |
| `pilot-last` / `chunk219.lean` | 236 | 6.99 | 8.34 | 10.112 | 1.1G | 0 | 19:45:46  up 388 days 22:52,  14 users,  load average: 32.62, 25.68, 15.97 |

The heaviest end pilot is `chunk218.lean`, entirely at `c = 88`.
The largest pilot peak is **1.9G**. Four times that reported peak is **7.6G**,
below **9 GiB**, satisfying the sizing rule without raising a cap.
Every pilot printed `'checked' depends on axioms: [propext]`.
Each `journalctl` command exited **0**.

### Length-90 failure and runner smoke check

`bad90.lean` uses exactly the same definitions, table certificate and chunk
theorem as the positive files, with `sample = [(14,79,89)]`, representing
distances **{0,14,79,89}**. The scoped `red90` command below exited **1**:

```text
bad90.lean:43:48: error: Tactic `decide` proved that the proposition
  checkSets sample = true
is false
'checked' depends on axioms: [propext, sorryAx]
```

The failed declaration's provisional axiom report is rejected by the runner.
No successful chunk uses that axiom. The table certificate completed before
the failing chunk theorem; the expected value and setup were unchanged.

`red90`: wall **2.527 s**, peak **486.3M**, exit **1**; starting uptime `19:46:22  up 388 days 22:52,  14 users,  load average: 23.62, 24.29, 15.91`. Journal retrieval exited **0**.

`smoke`: wall **4.707 s**, peak **1.5G**, exit **1**; starting uptime `19:46:30  up 388 days 22:52,  14 users,  load average: 22.93, 24.14, 15.91`. Journal retrieval exited **0**.

The same runner used for the full measurement checked four one-unit files
and the length-90 file, at most four at once, in its own 8 GiB scope:

```text
smoke: completed 5/5; failed: ['bad90.lean']; workers=4; wall=4.095722s
```

The four positive files exited 0 and the length-90 file exited 1. Both the
runner and scope returned 1, preserving the failure.

`data-edits`: wall **1.162 s**, peak **252M**, exit **0**; starting uptime `19:46:34  up 388 days 22:53,  14 users,  load average: 22.14, 23.95, 15.89`. Journal retrieval exited **0**.

`data-edits.lean` imports `Bitcoin.Bech32Codec` and contains exactly step 1's
definitions, preceded by the licence header and `open Bitcoin.Bech32`.
It produced no elaboration errors; the profiler printed cumulative
`type checking 0.91ms`. This checks the corrected definitions, without
proving decoder transport.

### Complete four-way measurement

Before the scope, `nix develop -c lake build` in `packages/bitcoin` exited
**0** (`Build completed successfully (27 jobs).`, **1.533 s**).
The complete measurement was performed exactly once. A single
`nix develop -c lake env` starts the runner, which launches
`lean -Dprofiler=true` directly, with four workers. All child stdout and
stderr streams were saved separately in scratch files.

The total wall time around the supervised scope command was **1198.049 s**.
Starting uptime was `19:46:50  up 388 days 22:53,  14 users,  load average: 18.37, 23.03, 15.72`; `nproc` printed **16**.
The scope command exited **0**, without timeout. Its journal command
exited **0** and reported:

```text
bech32-full-1954.scope: Consumed 1h 13min 54.977s CPU time over 19min 57.908s wall clock time, 6.2G memory peak.
```

There was no OOM or killed-process message. This measured **6.2G** four-way
peak replaces any parallel-memory estimate; the cap was **12 GiB**.
All **220/220** chunks exited **0**, with accepted kernel theorems and
`'checked' depends on axioms: [propext]`. The runner also checks that each
successful file has the profiler records and an allowed axiom report.
An event sweep over start/end timestamps found a maximum of **4**
simultaneous Lean processes. No other heavy check was started alongside it.

The [per-chunk TSV](bech32-4-error-chunks.tsv) contains each index, relative
filename, unit count, first and last tuple, start and end seconds relative
to runner startup, wall seconds, exit, chunk kernel seconds, cumulative
kernel seconds, axiom report and acceptance result. Runner-relative times
exclude environment startup; the total scope wall includes it.

| Measured quantity | Seconds |
|---|---:|
| Sum of per-chunk walls | 4762.876375 |
| Sum of chunk-theorem kernel times | 3838.900000 |
| Sum of cumulative kernel times | 4317.850000 |
| Total four-way scope wall | 1198.049 |
| Fastest: `chunk000.lean` (500 units) | 8.119947 |
| Slowest: `chunk180.lean` (500 units) | 33.434445 |

Kernel sums use the profiler's printed, rounded values. The wall sum counts
concurrent files separately and is not the total four-way wall. No projection
from representative slices or assumed per-file overhead enters the verdict.
The remaining proof costs are unmeasured and excluded.

The aggregate table and concurrency count can be recomputed from the TSV
with this command (exit **0**):

```bash
python3 - "$REPO/packages/bitcoin/docs/bech32-4-error-chunks.tsv" <<'PY'
import csv, sys
with open(sys.argv[1]) as stream:
    rows = list(csv.DictReader(stream, delimiter='\t'))
assert len(rows) == 220 and sum(int(r['units']) for r in rows) == 109736
assert all(r['exit'] == '0' and r['valid'] == 'True' for r in rows)
for field in ['wall_s', 'chunk_kernel_s', 'cumulative_kernel_s']:
    print(f"{field}: {sum(float(r[field]) for r in rows):.6f}")
for label, choose in [('fastest', min), ('slowest', max)]:
    row = choose(rows, key=lambda r: float(r['wall_s']))
    print(f"{label}: {row['file']} {row['wall_s']}s")
events = sorted([(float(r['start_s']), 1) for r in rows] +
                [(float(r['end_s']), -1) for r in rows])
active = peak = 0
for _, delta in events:
    active += delta
    peak = max(peak, active)
assert active == 0 and peak <= 4
print(f"maximum simultaneous Lean processes: {peak}")
PY
```

## Rerunnable scratch sources and commands

`REPO` is the repository root; `TMP_ROOT` is a fresh owned scratch directory
under the required experiment parent. Set `TMPDIR="$TMP_ROOT"`.
Save each source below with its displayed filename and a final newline.
No scratch Lean file belongs to the library or repository.

### `base-before-table.lean`

```lean
/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Bech32
open Bitcoin.Bech32
set_option maxRecDepth 16384
set_option maxHeartbeats 0

def insertRow (x : Nat) : List Nat → Option (List Nat)
  | [] => if x == 0 then none else some [x]
  | b :: bs =>
    if x == 0 then none
    else if b.log2 < x.log2 then some (x :: b :: bs)
    else if x.log2 == b.log2 then
      (insertRow (Nat.xor x b) bs).map (b :: ·)
    else (insertRow x bs).map (b :: ·)

def independent : List Nat → List Nat → Bool
  | [], _ => true
  | x :: xs, basis =>
    match insertRow x basis with
    | none => false
    | some next => independent xs next

def columns : Nat → List (List Nat)
  | 0 => []
  | n + 1 =>
    let rows := (List.range 5).map fun j =>
      ((List.replicate n (0 : BitVec 30)).foldl polymodStep
        (BitVec.ofNat 30 (2^j))).toNat
    columns n ++ [rows]
```

### `generate.py`

```python
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
import hashlib, pathlib
root = pathlib.Path(__file__).parent
rows = [1 << j for j in range(5)]
table = []
generators = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
def step(x):
    result = (x & 0x1ffffff) << 5
    for j, gen in enumerate(generators):
        if (x >> (25+j)) & 1:
            result ^= gen
    return result
for i in range(90):
    table.append(rows)
    rows = [step(x) for x in rows]
common = (root/"base-before-table.lean").read_text()
common += "\n\ndef table : List (List Nat) := " + repr(table) + "\n"
common += "theorem table_real : table = columns 90 := by decide +kernel\n"
common += """
def checkSets (sets : List (Nat × Nat × Nat)) : Bool :=
  sets.all fun (a,b,c) =>
    independent (table[0]! ++ table[a]! ++ table[b]! ++ table[c]!) []
"""
def source(sets):
    return (common + "\ndef sample : List (Nat × Nat × Nat) := " + repr(sets) + "\n"
            + "theorem checked : checkSets sample = true := by decide +kernel\n#print axioms checked\n")
triples = [(a,b,c) for c in range(89) for b in range(c) for a in range(1,b)]
assert len(triples) == 109736
manifest = []
for i, offset in enumerate(range(0,len(triples),500)):
    name = f"chunk{i:03d}.lean"
    data = source(triples[offset:offset+500]).encode()
    (root/name).write_bytes(data)
    manifest.append(hashlib.sha256(data).hexdigest()+"  "+name+"\n")
(root/"chunks.sha256").write_text("".join(manifest))
(root/"bad90.lean").write_text(source([(14,79,89)]))
for i in range(4):
    (root/f"smoke{i}.lean").write_text(source(triples[i:i+1]))
print(f"generated {len(manifest)} chunks; 109736 units; size 500; final 236")
print("manifest SHA-256: "+hashlib.sha256((root/"chunks.sha256").read_bytes()).hexdigest())
```

### `coverage.py`

```python
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
import ast, collections, itertools, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
files = sorted(root.glob("chunk[0-9][0-9][0-9].lean"))
actual = []
for i, path in enumerate(files):
    if path.name != f"chunk{i:03d}.lean":
        raise SystemExit("gap in chunk indices: " + path.name)
    match = re.search(r"^def sample : List .* := (.*)$", path.read_text(), re.M)
    if match is None:
        raise SystemExit("missing sample: " + path.name)
    actual.extend(ast.literal_eval(match[1]))
# Independent formulation: combinations, then colexicographic sorting.
expected = sorted(itertools.combinations(range(1,89),3), key=lambda t:(t[2],t[1],t[0]))
counts = collections.Counter(actual)
duplicates = [t for t,n in counts.items() if n != 1]
missing = set(expected) - set(actual)
extra = set(actual) - set(expected)
if duplicates or missing or extra or actual != expected:
    print(f"FAIL: count={len(actual)}; duplicates={len(duplicates)}; missing={len(missing)}; extra={len(extra)}")
    if missing:
        print("first missing: " + repr(min(missing)))
    raise SystemExit(1)
assert len(actual) == 109736
print(f"PASS: {len(files)} chunks; 109736 units; exact triples 89 order; no gaps, duplicates or extras")
```

### `runner.py`

```python
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
import ast, concurrent.futures, csv, json, pathlib, re, subprocess, sys, time
root = pathlib.Path(__file__).parent
mode = sys.argv[1]
assert mode in ("smoke", "full")
names = ([f"smoke{i}.lean" for i in range(4)] + ["bad90.lean"] if mode == "smoke"
         else [f"chunk{i:03d}.lean" for i in range(220)])
started = time.monotonic()
def seconds(value, unit):
    return float(value) / (1000 if unit == "ms" else 1)
def check(item):
    index, name = item
    source = (root/name).read_text()
    sample = ast.literal_eval(re.search(r"^def sample : List .* := (.*)$", source, re.M)[1])
    begin = time.monotonic() - started
    with (root/(mode+"-"+name+".stdout")).open("w") as out, (root/(mode+"-"+name+".stderr")).open("w") as err:
        p = subprocess.run(["lean", "-Dprofiler=true", str(root/name)], stdout=out, stderr=err)
    end = time.monotonic() - started
    text = (root/(mode+"-"+name+".stdout")).read_text()+"\n"+(root/(mode+"-"+name+".stderr")).read_text()
    kernels = re.findall(r"^type checking took ([0-9.]+)(ms|s)$", text, re.M)
    totals = re.findall(r"^\ttype checking ([0-9.]+)(ms|s)$", text, re.M)
    axioms = re.findall(r"^'checked' depends on axioms: \[(.*)\]$", text, re.M)
    valid = (p.returncode == 0 and len(kernels) >= 1 and len(totals) == 1 and len(axioms) == 1
             and set(filter(None, axioms[0].split(", "))) <= {"propext", "Classical.choice", "Quot.sound"})
    return dict(index=index, file=name, units=len(sample), first=repr(sample[0]), last=repr(sample[-1]),
                start_s=round(begin,6), end_s=round(end,6), wall_s=round(end-begin,6), exit=p.returncode,
                chunk_kernel_s=seconds(*kernels[-1]) if kernels else "",
                cumulative_kernel_s=seconds(*totals[0]) if totals else "",
                axioms="'checked' depends on axioms: ["+axioms[0]+"]" if axioms else "", valid=valid)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    records = list(pool.map(check, enumerate(names)))
(root/(mode+"-records.json")).write_text(json.dumps(records,indent=2)+"\n")
with (root/(mode+"-records.tsv")).open("w") as stream:
    writer = csv.DictWriter(stream,fieldnames=list(records[0]),delimiter="\t",lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
failed = [r["file"] for r in records if not r["valid"]]
print(f"{mode}: completed {len(records)}/{len(names)}; failed: {failed}; workers=4; wall={time.monotonic()-started:.6f}s")
raise SystemExit(1 if failed else 0)
```

### `invoke.py`

```python
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
import json, os, pathlib, shlex, shutil, subprocess, sys, time
root = pathlib.Path(__file__).parent
label, cwd, *command = sys.argv[1:]
bash = shutil.which("bash")
if bash is None:
    raise SystemExit("bash is required")
gate = root / (label + ".bash")
gate.write_text("cd " + shlex.quote(cwd) + "\n" + shlex.join(command) + "\n")
env = os.environ.copy()
env.update(TMPDIR=str(root), SPIKE_GATE_BASH=bash, SPIKE_GATE_FILE=str(gate))
with (root/(label+".stdout")).open("w") as out, (root/(label+".stderr")).open("w") as err:
    host_load = subprocess.check_output(["uptime"], text=True).strip()
    started = time.monotonic()
    result = subprocess.run([bash, str(root/"supervise.bash")], env=env, stdout=out, stderr=err)
elapsed = time.monotonic() - started
record = dict(label=label, command=command, exit=result.returncode, wall=round(elapsed,3), uptime=host_load)
if "--scope" in command:
    unit = next(arg.split("=",1)[1] for arg in command if arg.startswith("--unit="))
    journal = subprocess.run(["journalctl", "--user", "-u", unit+".scope", "--no-pager", "-o", "cat"], capture_output=True, text=True)
    (root/(label+".journal")).write_text(journal.stdout)
    (root/(label+".journal-stderr")).write_text(journal.stderr)
    record.update(journal_exit=journal.returncode, memory=journal.stdout)
(root/(label+".json")).write_text(json.dumps(record)+"\n")
print((root/(label+".stdout")).read_text(), end="")
print((root/(label+".stderr")).read_text(), end="", file=sys.stderr)
print(json.dumps(record), flush=True)
sys.exit(result.returncode)
```

### `prepare-supervisor.py`

```python
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
import pathlib, sys
root, repo = map(pathlib.Path, sys.argv[1:])
a = (repo/"AGENTS.md").read_text()
s = "POSIXLY_CORRECT=y\n" + a.split("```bash\nPOSIXLY_CORRECT=y\n",1)[1].split("\n```",1)[0]
assert s.count("<gate>") == 1
s = s.replace("<gate>", '\"$SPIKE_GATE_BASH\" --noprofile --norc -eo pipefail \"$SPIKE_GATE_FILE\"')
start = s.index("try:\n    os.kill(watchdog_pid, signal.SIGTERM)")
end = s.index("\nrc = 1", start)
s = s[:start] + s[end:]
start = s.index("_gate_owner_pid=$BASHPID")
s = s[:start] + '''command exec "$_gate_python" -I "$_gate_runner" "$_gate_dir" "${BASH:-bash}" 0 "$_gate_pending"
__AGENT_GATE_WRAPPER__
'''
(root/"supervise.bash").write_text(s)
```

The supervisor setup uses the repository's gate wrapper, omitting its
bootstrap watchdog to keep shell commands in the foreground. Its process
group supervision, status propagation, separate streams and exact-path
cleanup remain enabled. The setup's byte comparison with the wrapper used
for these measurements exited **0**. The runner's four foreground children
are the required bounded concurrency.

### Commands

From the repository root, after saving the sources, prepare and generate:

```bash
python3 "$TMP_ROOT/prepare-supervisor.py" "$TMP_ROOT" "$REPO"
python3 "$TMP_ROOT/generate.py"
python3 "$TMP_ROOT/coverage.py" "$TMP_ROOT" > "$TMP_ROOT/coverage.stdout" 2> "$TMP_ROOT/coverage.stderr"
```

All three exited **0**. Create the coverage-failure copy with this command
(exit **0**); only the owned copy loses one tuple:

```bash
python3 - "$TMP_ROOT" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
red = root/'coverage-red'
red.mkdir()
for p in sorted(root.glob('chunk[0-9][0-9][0-9].lean')):
    if p.name == 'chunk000.lean':
        text = p.read_text()
        assert '[(1, 2, 3), ' in text
        (red/p.name).write_text(text.replace('[(1, 2, 3), ', '[', 1))
    else:
        (red/p.name).symlink_to(p)
PY
python3 "$TMP_ROOT/coverage.py" "$TMP_ROOT/coverage-red" > "$TMP_ROOT/coverage-red.stdout" 2> "$TMP_ROOT/coverage-red.stderr"
```

The final command exits **1**, with the missing-tuple diagnostic above.
The package build before the full scope was invoked as follows (exit **0**):

```bash
python3 "$TMP_ROOT/invoke.py" prebuild "$REPO/packages/bitcoin" nix develop -c lake build
```

The pilot commands, in order, each exited **0**:

```bash
while read -r label source suffix; do
  python3 "$TMP_ROOT/invoke.py" "$label" "$REPO/packages/bitcoin" \
    systemd-run --user --scope --quiet --unit="bech32-$label-$suffix" \
    -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue \
    timeout 3600 nix develop -c lake env lean -Dprofiler=true "$TMP_ROOT/$source"
done <<'PILOTS'
pilot-start chunk000.lean 1950
pilot-middle chunk110.lean 1951
pilot-heavy chunk218.lean 1951
pilot-last chunk219.lean 1951
PILOTS
```

The next commands exited **1**, **1**, and **0**, respectively. Save step 1's
definitions as `data-edits.lean`, with the licence header, the import and
namespace opening described above. No case-preservation definition is included.

```bash
python3 "$TMP_ROOT/invoke.py" red90 "$REPO/packages/bitcoin" \
  systemd-run --user --scope --quiet --unit=bech32-red90-1952 \
  -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue \
  timeout 3600 nix develop -c lake env lean -Dprofiler=true "$TMP_ROOT/bad90.lean"
python3 "$TMP_ROOT/invoke.py" smoke "$REPO/packages/bitcoin" \
  systemd-run --user --scope --quiet --unit=bech32-smoke-1953 \
  -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue \
  timeout 3600 nix develop -c lake env python3 "$TMP_ROOT/runner.py" smoke
python3 "$TMP_ROOT/invoke.py" data-edits "$REPO/packages/bitcoin" \
  systemd-run --user --scope --quiet --unit=bech32-data-edits-1953 \
  -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue \
  timeout 3600 nix develop -c lake env lean -Dprofiler=true "$TMP_ROOT/data-edits.lean"
```

The complete measurement command (exit **0**) was:

```bash
nproc > "$TMP_ROOT/full-nproc.stdout"
python3 "$TMP_ROOT/invoke.py" full "$REPO/packages/bitcoin" \
  systemd-run --user --scope --quiet --unit=bech32-full-1954 \
  -p MemoryMax=12G -p MemorySwapMax=0 -p OOMPolicy=continue \
  timeout 3600 nix develop -c lake env python3 "$TMP_ROOT/runner.py" full
```

The helper obtains each scope's journal with this command (each exited **0**):

```bash
journalctl --user -u "$unit.scope" --no-pager -o cat
```

Use fresh unit names for any single-file repetition. Every Lean experiment
except the complete four-way measurement above had its own 8 GiB scope.
The full check was not sent through the sandbox or repeated.

## Library and mutation evidence

The following records describe the checksum residue lemma and its mutation
checks. The library files are unchanged, so these mutation commands were not
repeated.

The lemma's profile command, from `packages/bitcoin`, was
`nix develop -c lake env lean -Dprofiler=true Bitcoin/Bech32Detection.lean`:
exit **0**, cumulative kernel checking **0.312 ms**.

The named theorem has this output:

```text
'Bitcoin.Bech32.verifyChecksum_residue_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
Bitcoin axiom gate: 503 library theorems; 43 named; 0 offenders
```

The new allowlist entry was tested by temporarily declaring
`Bitcoin.Bech32.residue_eq_test` with exactly the theorem's arguments and result,
then replacing only the proof with `exact residue_eq_test v hrp d d' valid valid'`.
`nix develop -c lake test` exited **1** at the gate:

```text
BitcoinTests/AxiomGate.lean:67:0: Bitcoin axiom gate: Bitcoin.Bech32.verifyChecksum_residue_eq reaches disallowed axiom Bitcoin.Bech32.residue_eq_test
```

The axiom and temporary proof were removed; the same command exited **0**.
The theorem kept its name throughout, so this failure exercised the allowlist
rather than name resolution. No existing definition or theorem statement was
mutated by this test.

The four foreground commands below, from `$REPO/packages/bitcoin`, all
exited **0**, in this order. Each final restored `lake test` exited **0**:

| Command | Detected | Wall seconds |
|---|---:|---:|
| `nix develop -c python3 -I check-mutations.py` | 6/6 | 51.009 |
| `nix develop -c python3 -I check-base58-mutations.py` | 6/6 | 51.852 |
| `nix develop -c python3 -I check-bech32-mutations.py` | 18/18 | 218.586 |
| `nix develop -c python3 -I check-address-mutations.py` | 20/20 | 153.553 |

The only runner source edits are the pinned `42 named; 0 offenders` to
`43 named; 0 offenders` literals in the bech32 and address scripts. Mutation
targets, replacement strings, theorem names and expected assertions are
unchanged. The new lemma still checks under the generator, variant-constant,
charset, HRP and decoder runtime mutations, so their recorded assertions
remain the detection point after a passing gate.

Only one regenerated record moved: `test-data/mutations.json`, label `axiom`,
`BitcoinTests/AxiomGate.lean:66:0` to **67:0**. Its axiom name, diagnostic text,
exit and detection kind are identical. All other records in all four JSON
files are unchanged, including the three complete other files.

## Validation and cleanup

README's Phase 3b section records the final package build/test, sandbox check,
default build, final derivation log, six library hashes, unchanged-library
comparison, hygiene checks and cleanup commands with their observed exits.
The derivation is evaluated after the last edit to this document and the TSV,
because `packages/` belongs to the flake source set. README is outside that set.

No reference clone, Mathlib source, package or flake input was added.
The scratch sources above preserve the experiment; chunk files are not
committed. Gate wrappers remove their own private files by exact path.
