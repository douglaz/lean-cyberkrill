# Upstream fixes

These notes concern `pure-algebra/lean4-hash` at
`ab7eda433f0390fde7aa240189761540c9744c79` (MIT). Paths and line numbers below
refer to that revision. Sending patches remains Phase 10 work.

| File | Problem | Fix used in this port |
|---|---|---|
| `Hash/Sha256/Spec.lean` | Lean 4.35 deprecates `if_pos` at line 156, `dif_neg` at 264 and 344, and `dif_pos` at 340; warnings fail the build. | Use `ite_eq_left`, `dite_eq_right`, and `dite_eq_left`, respectively. Statements and proof steps otherwise stay unchanged. |
| `Hash/Sha256/Impl.lean` | `dif_pos` at 85 and `dif_neg` at 89 are deprecated. | Use `dite_eq_left` and `dite_eq_right`. |
| `Hash/Sha256/Fast.lean` | `dif_pos` twice at 173 and once at 263, and `dif_neg` twice at 174 and once at 265 are deprecated. | Use `dite_eq_left` and `dite_eq_right`. |
| `Hash/Sha256/Digest.lean` | `dif_pos` at 74 is deprecated. | Use `dite_eq_left`. |
| `Hash/Sha256/Api.lean` | The trust-base docstring hard-codes a kernel version and an external recheck target; either becomes misleading in a partial port. | Name the actual kernel and audit used by the build. This port names Lean 4.35.0 and its allowlist gate, without claiming an external recheck. |
| `Hash/Sha256/Api.lean` | Five build-time witnesses prevent a deliberately wrong but mutually consistent `Spec.K`/`Fast.K` from reaching executable vectors. | Cover all five witnesses in the counted runtime ShortMsg suite; remove the five guards and their now-unused meta imports. This lets proofs check while all four vector sets fail on the changed constant. |

The module/namespace rename and the doc clarifications about upstream-only
paths and tests are local integration changes, rather than proposed upstream
semantic changes. No theorem statement is weakened.
