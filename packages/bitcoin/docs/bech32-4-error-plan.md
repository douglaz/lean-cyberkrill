# Phase 3b (1 of 2): four-data-error proof feasibility

## Verdict: stop

The certified literal-column checker projects to **2,581–4,412 s single-core**
for the finite check and measured file overhead, exceeding the **600 s added
sandbox-build budget**. The remaining proof cost is unmeasured and excluded.
Memory also forces chunking: a 1,500-unit file peaks at **5.1G** in the scope
journal, while the larger-file capacity measurements below reach the 8 GiB cap.
The proposed shape is **74 files, one declaration of at most 1,500 units per file**.
These are repeated representative extrapolations, not a completed full check
or a proven build-time bound. No full check was attempted because the estimate
exceeds 600 s. Other algorithms and parallel module builds are unmeasured.

No weaker theorem is proposed. The full theorem remains unproved. Mathlib is
not needed by this plan: structural list induction, bit extensionality and
binary elimination suffice in Lean core. No `bitcoin-proofs` package, dependency
or flake input is needed or added. No full finite checker or soundness proof is
added to the library.

## The unchanged target

For each variant, as claimed by [BIP173, Checksum](https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0173.mediawiki#checksum)
and [BIP350](https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0350.mediawiki),
for a string valid under variant v (bech32 or bech32m) whose data part is at most
89 characters, any substitution of 1 to 4 data characters yields a string that
variant v's checksum verification rejects. Both sources are pinned to
bitcoin/bips commit `130b8e0fa7f30fa45532f080b87b8db27a79e46e`.

Data characters are **all characters after the separator, including the six
checksum characters**. Substitutions use the bech32 charset, preserving HRP,
separator position and case. With `Symbol := BitVec 5`, the intended Lean
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
charset character with the HRP, separator position and case unchanged, then
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
   count as edits. `sameCaseEdit` permits a digit in either letter case.

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

   def sameCaseEdit (c c' : Char) : Prop :=
     c = c' ∨ ∃ x y : Symbol,
       (c = charOf x ∧ c' = charOf y) ∨
       (c = (charOf x).toUpper ∧ c' = (charOf y).toUpper)

   def DataEdits (s t : String) (k : Nat) : Prop :=
     ∃ h xs ys,
       dataParts s.toList = some (h, xs) ∧
       dataParts t.toList = some (h, ys) ∧
       xs.length = ys.length ∧
       (∀ c ∈ xs ++ ys, ∃ x : Symbol, c.toLower = charOf x) ∧
       (∀ p ∈ xs.zip ys, sameCaseEdit p.1 p.2) ∧
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
   assumption about `t` is added to the corollary.

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
   is **0.312 ms** (the accepted earlier profile).

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

6. **Exhaustiveness and the final finite fact.** Use 74 files, with one chunk
   theorem of at most 1,500 units per file, rather than one kernel reduction
   over the entire enumeration. Each file contains the same table certificate
   and the same checker definitions as the measured files. There are 73 full
   chunks and a last chunk of 236 units. The three nested structural ranges
   enumerate exactly `0 < a < b < c < 89`. Required assembly and coverage
   statements are:

   ```lean
   def triples (n : Nat) : List (Nat × Nat × Nat) :=
     (List.range n).flatMap fun c =>
       (List.range c).flatMap fun b =>
         (List.range b).filterMap fun a =>
           if 0 < a then some (a,b,c) else none

   def chunks : List (List (Nat × Nat × Nat)) :=
     (List.range 74).map fun i => ((triples 89).drop (1500 * i)).take 1500

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
   timing sum. Table and literal-list identity certificates must be carried
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
chunk-assembly proofs are unmeasured. Their cost is excluded from the estimate;
no numerical allowance is added. The finite check alone decides the stop verdict.

## Representative measurements

The only checker variant measured here is binary elimination over a literal
column table, kernel-certified equal to `columns 90` from the real
`polymodStep`. Each table is generated once per file. Neither real-column
construction nor table certification occurs per unit. The verdict rests on
this variant; no further algorithms were explored.

One unit is a normalized tuple `(a,b,c)` with implicit distance zero. The
structural enumeration `triples 89` has `88 * 87 * 86 / 6 = 109736` units.
The generator below uses exactly that order. Start slices begin at offset 0,
middle slices at 54,118, and end slices at 108,236; both sizes at a location
share the same starting offset. The end 1,500 slice ends at offset 109,736.
Every size and location was measured twice, sequentially on CPU 0. The scope
contains the whole file, including imports, definitions, table certificate,
literal sample elaboration and chunk theorem. Thus the peaks are per-file
measurements of the proposed one-declaration-per-file build shape.

Measured on 2026-10-22. `lscpu` (exit 0) reported AMD Ryzen 7 7700 8-Core
Processor, eight cores, sixteen logical CPUs and two threads per core.
`systemd-run --version` (exit 0) reported systemd 260 (260.5).
The final package validation records `nix develop -c lean --version` in README.
The experiments use Lean 4.35.0 from the same development environment.

`Chunk kernel` is the profiler's final `type checking took` line for the
chunk theorem. `All kernel` is cumulative type checking, including the
separate table certificate and definitions. Wall time is measured around the
supervised invocation, including startup and cleanup. Profiler times are
rounded as printed. Starting uptime is captured immediately before each
invocation. Peaks are the journal's human-readable M/G values, without
inventing extra precision. Each journal command exited 0. Both streams were
captured separately before replay; no pipe determines any gate status.

| Location, units, repeat | Chunk kernel s | All kernel s | Wall s | Scope peak | Exit | Starting uptime |
|---|---:|---:|---:|---:|---:|---|
| `start500-r1` | 4.39 | 5.63 | 7.176 | 1018.5M | 0 | 18:41:32  up 388 days 21:48,  15 users,  load average: 6.28, 8.23, 10.21 |
| `start1500-r1` | 16.3 | 18 | 19.974 | 2.6G | 0 | 18:41:52  up 388 days 21:48,  15 users,  load average: 7.03, 8.27, 10.18 |
| `start500-r2` | 4.29 | 5.48 | 6.988 | 1G | 0 | 18:42:12  up 388 days 21:48,  15 users,  load average: 6.32, 8.03, 10.06 |
| `start1500-r2` | 15.8 | 17.4 | 19.354 | 2.6G | 0 | 18:42:19  up 388 days 21:48,  15 users,  load average: 6.38, 8.01, 10.04 |
| `middle500-r1` | 12 | 13.1 | 14.623 | 1.9G | 0 | 18:42:38  up 388 days 21:49,  15 users,  load average: 5.43, 7.68, 9.89 |
| `middle1500-r1` | 35.7 | 37.4 | 39.631 | 4.9G | 0 | 18:42:53  up 388 days 21:49,  15 users,  load average: 5.42, 7.57, 9.82 |
| `middle500-r2` | 12.8 | 14.2 | 15.797 | 1.9G | 0 | 18:43:32  up 388 days 21:50,  15 users,  load average: 5.87, 7.39, 9.66 |
| `middle1500-r2` | 33.2 | 35 | 37.193 | 4.9G | 0 | 18:43:48  up 388 days 21:50,  15 users,  load average: 5.91, 7.32, 9.60 |
| `end500-r1` | 10.7 | 12 | 13.591 | 1.9G | 0 | 18:44:26  up 388 days 21:50,  15 users,  load average: 6.26, 7.25, 9.49 |
| `end1500-r1` | 38.9 | 40.7 | 43.220 | 5.1G | 0 | 18:44:39  up 388 days 21:51,  15 users,  load average: 5.84, 7.11, 9.41 |
| `end500-r2` | 23.4 | 25.7 | 29.078 | 2G | 0 | 18:45:22  up 388 days 21:51,  15 users,  load average: 8.61, 7.54, 9.44 |
| `end1500-r2` | 49.8 | 52.7 | 57.410 | 5.1G | 0 | 18:45:52  up 388 days 21:52,  15 users,  load average: 15.19, 9.19, 9.93 |

The fixed files contain all shared definitions and the table certificate,
with `checkSets [] = true`; they measure imports and setup separately.
The other diagnostic records are:

| Purpose, repeat | All kernel s | Wall s | Scope peak | Exit | Starting uptime |
|---|---:|---:|---:|---:|---|
| `fixed-r1` | 0.85 | 2.255 | 492.1M | 0 | 18:41:25  up 388 days 21:47,  15 users,  load average: 6.52, 8.35, 10.27 |
| `fixed-r2` | 0.819 | 2.192 | 491.8M | 0 | 18:41:50  up 388 days 21:48,  15 users,  load average: 6.77, 8.24, 10.18 |
| `capacity6000-r1` | not completed | 59.835 | 8G | 137 | 18:46:55  up 388 days 21:53,  15 users,  load average: 17.29, 11.12, 10.56 |
| `capacity6000-r2` | not completed | 57.290 | 8G | 137 | 18:47:55  up 388 days 21:54,  15 users,  load average: 9.98, 10.23, 10.29 |
| `bad90-r1` | 1.1 | 3.108 | 495.5M | 1 | 18:46:49  up 388 days 21:53,  15 users,  load average: 16.27, 10.82, 10.46 |
| `data-edits-r1` | 0.00077 | 1.205 | 255.3M | 0 | 18:48:52  up 388 days 21:55,  15 users,  load average: 7.43, 9.48, 10.03 |

Successful slice theorems printed `[propext]`; `table_real` printed
`[propext, Quot.sound]`. No unapproved evaluation axiom is involved.
`data-edits-r1` checks the proposed definitions from step 1 as a complete
file importing `Bitcoin.Bech32Codec`; it does not prove decoder transport.

### Fixed and marginal split

For each matched repeat, let `K500` and `K1500` be chunk kernel times.
The measured marginal cost is `(K1500 - K500) / 1000`, excluding table
certification from the per-unit term. For each pair the file-cost residual
is `max(W500 - 500*m, W1500 - 1500*m)`. This includes imports, table setup,
certification, elaboration and the measured kernel intercept. It is an
empirical envelope, not a claim that all this residual is intrinsically
constant. The baseline fixed-file walls are 2.255 and 2.192 s. All
non-checking per-file costs are retained rather than added as an unmeasured
allowance.

| Location, repeat | Marginal kernel s/unit | File-cost residual s |
|---|---:|---:|
| start, 1 | (16.3 − 4.39) / 1000 = 0.01191 | 2.109 |
| start, 2 | (15.8 − 4.29) / 1000 = 0.01151 | 2.089 |
| middle, 1 | (35.7 − 12) / 1000 = 0.02370 | 4.081 |
| middle, 2 | (33.2 − 12.8) / 1000 = 0.02040 | 6.593 |
| end, 1 | (38.9 − 10.7) / 1000 = 0.02820 | 0.920 |
| end, 2 | (49.8 − 23.4) / 1000 = 0.02640 | 17.810 |

Use the maximum observed residual, **17.810 s/file**, including the
fixed-file baseline in that maximum. With one declaration per file,
`ceil(109736 / 1500) = 74` files (73 × 1500 + 236 = 109736):

```text
lower observed slope: 0.01151 × 109736 = 1263.06136 s
worst location (end): 0.02820 × 109736 = 3094.55520 s
measured file envelope: 17.810 × 74 = 1317.940 s
lower projection: 1263.06136 + 1317.940 = 2581.00136 s
upper projection: 3094.55520 + 1317.940 = 4412.49520 s
```

This extrapolates representative slices; it is not a measured full sum or a
proven upper bound. Even the lowest observed marginal finite term exceeds
600 s. The algebraic, soundness, coverage and assembly proofs are unmeasured
and excluded, with no numerical guess for them. No full chunked check is
justified under the verdict rule. CI hardware is unmeasured.

### Memory and check shape

The measured 500-unit files peak at approximately 1.0–2.0G; the 1,500-unit
files peak at 2.6–5.1G. This growth makes a single declaration over 109,736
units an unsuitable plan. The separate 6,000-unit capacity files use the
same checker, table certificate and one declaration over a middle slice.
Their scopes record the capacity failures below. Those failures are not
used as time samples for the extrapolation.

The proposed build uses 1,500 units per declaration and one declaration per
file: **74 files**, with a last 236-unit chunk. Its measured worst per-file
peak is **5.1G**, leaving approximately **2.9G** below the 8 GiB limit. This
margin is measured on the sampled files, not asserted for every possible
chunk. Assembly and exact coverage obligations are in step 6. No single
full-size kernel decision is proposed.

Parallel module builds were not measured. N parallel jobs would consume
about N times the per-file peak; neither that memory total nor a speedup is
measured. No parallel build estimate enters the verdict.

### Non-vacuity and capacity diagnostics

On the verdict's certified-table checker, the length-90 test uses the
normalized tuple `(14,79,89)`, hence distances {0,14,79,89}. Its command is
the same scoped helper invocation below with label `bad90-r1` and source
`bad90.lean`. It exits **1**, printing:

```text
Tactic `decide` proved that the proposition
  checkSets [(14, 79, 89)] = true
is false
```

The certificate completed before that failure. The failure pins the same
independence check used in the positive slices, rather than changing the
expected value or the test setup. The two capacity invocations use labels
`capacity6000-r1` and `capacity6000-r2` and source `capacity6000.lean`.
Their observed scope messages, with owned paths omitted, are:

```text
bech32-capacity6000-r1-1843.scope: The kernel OOM killer killed some processes in this unit.
bech32-capacity6000-r1-1843.scope: Consumed 59.374s CPU time over 59.682s wall clock time, 8G memory peak.
bech32-capacity6000-r2-1843.scope: The kernel OOM killer killed some processes in this unit.
bech32-capacity6000-r2-1843.scope: Consumed 56.925s CPU time over 57.161s wall clock time, 8G memory peak.
```

## Rerunnable scratch sources and commands

`REPO` is the repository root and `TMP_ROOT` a fresh owned scratch directory.
Keep `TMPDIR` under the scratch parent specified by the experiment rules;
inside the helper it is set to `TMP_ROOT`. Save the following sources there.
No scratch Lean file is a library import or a separate repository file.

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
import pathlib
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
(root/"common.lean").write_text(common)
triples = [(a,b,c) for c in range(89) for b in range(c) for a in range(1,b)]
assert len(triples) == 109736
for location, start in [("start",0),("middle",54118),("end",108236)]:
    for size in [500,1500]:
        sets = triples[start:start+size]
        source = common + "\ndef sample : List (Nat × Nat × Nat) := " + repr(sets) + "\n"
        source += "theorem checked : checkSets sample = true := by decide +kernel\n#print axioms checked\n"
        (root/(location+str(size)+".lean")).write_text(source)
(root/"fixed.lean").write_text(common + "\ntheorem checked : checkSets [] = true := by decide +kernel\n#print axioms table_real\n")
(root/"bad90.lean").write_text(common + "\ntheorem checked : checkSets [(14,79,89)] = true := by decide +kernel\n")

sets = triples[54118:60118]
source = common + "\ndef sample : List (Nat × Nat × Nat) := " + repr(sets) + "\n"
source += "theorem checked : checkSets sample = true := by decide +kernel\n#print axioms checked\n"
(root/"capacity6000.lean").write_text(source)
```

The generator writes the shared definitions, literal table and real-column
certificate into each complete file. It generates exactly the literal lists
used in the measurements; it does not certify list coverage or soundness.
Save step 1's definitions as `data-edits.lean`, preceded by the licence
header above, `import Bitcoin.Bech32Codec` and `open Bitcoin.Bech32`.

### Timing and supervision helper

Save the complete supervisor snippet from `AGENTS.md` as `supervise.bash`,
replacing its single `<gate>` line with exactly:

```bash
"$SPIKE_GATE_BASH" --noprofile --norc -eo pipefail "$SPIKE_GATE_FILE"
```

Save this measured helper as `invoke.py`. Bash is resolved from PATH; no
host-specific executable path is assumed.

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

The source-generation command is `python3 "$TMP_ROOT/generate.py"` (exit 0).
For each table label, the measured command has this exact shape; `source` is
the label with its `-r1`/`-r2` suffix removed. The source for both fixed labels
is `fixed.lean`, for both capacity labels `capacity6000.lean`, and for the
other diagnostics `bad90.lean` and `data-edits.lean`. All unit names have the
same `-1843` suffix shown here; use fresh names when repeating measurements.

```bash
python3 "$TMP_ROOT/invoke.py" "$label" "$REPO/packages/bitcoin" \
  systemd-run --user --scope --quiet --unit="bech32-$label-1843" \
  -p MemoryMax=8G -p MemorySwapMax=0 -p OOMPolicy=continue \
  timeout 3600 nix develop -c lake env taskset -c 0 lean -Dprofiler=true \
  "$TMP_ROOT/$source.lean"
```

The helper retrieves peak memory with:

```bash
journalctl --user -u "bech32-$label-1843.scope" --no-pager -o cat
```

Each kernel file was checked sequentially in its own foreground scope,
with no simultaneous experiment or flake check, zero swap and a 3600 s
limit. No cap was raised. No timeout or recursion-limit error was observed.
The capacity failures and expected false theorem retain their nonzero exits.

## Accepted library and mutation evidence

The following records are from the accepted earlier validation of the frozen
library change; the mutation commands were not repeated for this measurement
correction.


The new named theorem has this output:

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

README's Phase 3b section records the final package build/test, sandbox flake
check, default build, final derivation log, frozen-file hashes, unchanged-tree
comparison, hygiene checks and cleanup commands with their observed exits.
The derivation is evaluated only after the last edit to this document because
`packages/` belongs to the flake source set. README is outside that source set.

Only the proof plan and README are corrected here. No reference clone,
Mathlib source, package, flake input or additional library definition is added.
Scratch sources survive in the fenced records above. Each gate supervisor
removes its own private files by exact path before reporting its exit.
