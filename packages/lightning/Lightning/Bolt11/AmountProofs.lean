/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Bolt11.Codec
import Init.Data.Nat.ToString
import Init.Data.String.Lemmas.Pattern.TakeDrop.String

namespace Lightning.Bolt11

/-- Representation is a bound on the actual pico product, not a parser equation.
An absent amount has no unit. No-multiplier overflow HRPs remain decodable but
are outside this exact, writable amount domain. -/
def RepresentableHrp (hrp : Hrp) : Prop :=
  match hrp.rawAmount with
  | none => hrp.multiplier = none
  | some n => n.toNat * (hrp.multiplier.map Multiplier.factor).getD 1000000000000 < 2^64

theorem checkPrecision_rejects (hrp : Hrp) (pico : Nat)
    (available : hrp.picoAmount = some pico) (imprecise : pico % 10 ≠ 0) :
    checkPrecision hrp = .error .impreciseAmount := by
  unfold checkPrecision
  rw [available]
  change (if pico % 10 ≠ 0 then Except.error Error.impreciseAmount else .ok ()) = _
  rw [ite_eq_left imprecise]

theorem checkPrecision_accepts (hrp : Hrp) (pico : Nat)
    (available : hrp.picoAmount = some pico) (precise : pico % 10 = 0) :
    checkPrecision hrp = .ok () := by
  unfold checkPrecision
  rw [available]
  change (if pico % 10 ≠ 0 then Except.error Error.impreciseAmount else .ok ()) = _
  simp [precise]

theorem checkPrecision_unavailable (hrp : Hrp) (unavailable : hrp.picoAmount = none) :
    checkPrecision hrp = .ok () := by
  simp only [checkPrecision, unavailable]
  rfl

private theorem unit_pico (currency : Currency) (pico : Nat) (m : Option Multiplier)
    (factor : Nat) (factorEq : (m.map Multiplier.factor).getD 1000000000000 = factor)
    (bound : pico < 2^64)
    (exactUnit : pico % factor = 0) :
    (Hrp.mk currency (some (UInt64.ofNat (pico / factor))) m).picoAmount = some pico := by
  have quotient : pico / factor < 2^64 := Nat.lt_of_le_of_lt (Nat.div_le_self _ _) bound
  have product : pico / factor * factor = pico := Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero exactUnit)
  unfold Hrp.picoAmount
  simp only [factorEq]
  change (if (UInt64.ofNat (pico / factor)).toNat * factor < 2^64 then
    some ((UInt64.ofNat (pico / factor)).toNat * factor) else none) = _
  simp only [UInt64.toNat_ofNat',
    Nat.mod_eq_of_lt quotient]
  change (if pico / factor * factor < 2^64 then some (pico / factor * factor) else none) = _
  rw [product, ite_eq_left bound]

private theorem amount_of_pico (hrp : Hrp) (a : Bitcoin.Amount)
    (hp : hrp.picoAmount = some (10 * a.msat)) : hrp.amount = some a := by
  simp only [Hrp.amount, hp, Option.map_some]
  congr 1
  cases a
  simp [Bitcoin.Amount.ofMsat]

set_option linter.unusedSimpArgs false in
/-- Every canonical unit branch preserves pico and whole-msat amounts, for all currencies. -/
theorem hrpFromMsat_exact (currency : Currency) (a : Bitcoin.Amount)
    (bound : 10 * a.msat < 2^64) :
    ∃ hrp, hrpFromMsat currency a = .ok hrp ∧
      hrp.currency = currency ∧ hrp.picoAmount = some (10 * a.msat) ∧ hrp.amount = some a := by
  have hb : ¬ a.msat * 10 ≥ 2^64 := by omega
  unfold hrpFromMsat
  simp only [hb, ↓reduceIte, List.find?_cons, List.find?_nil,
    show (a.msat * 10 % 1 == 0) = true by simp [Nat.mod_one]]
  repeat' split
  all_goals
    simp only [Option.getD_some, Option.getD_none]
    refine ⟨_, rfl, rfl, ?_, ?_⟩
  all_goals try apply amount_of_pico
  all_goals
    rw [Nat.mul_comm 10 a.msat]
    apply unit_pico
  all_goals simp_all [Multiplier.factor, Nat.mod_one]

theorem hrpFromMsat_overflow (currency : Currency) (a : Bitcoin.Amount)
    (overflow : 2^64 ≤ 10 * a.msat) :
    hrpFromMsat currency a = .error .amountOverflow := by
  have h : a.msat * 10 ≥ 2^64 := by omega
  simp only [hrpFromMsat, h, ↓reduceIte]
  rfl

/-- Reverse canonicalization preserves the amount, without preserving units or spelling. -/
theorem hrp_amount_canonical (hrp : Hrp) (pico : Nat)
    (available : hrp.picoAmount = some pico) (precise : pico % 10 = 0) :
    ∃ canonical, hrpFromMsat hrp.currency (Bitcoin.Amount.ofMsat (pico / 10)) = .ok canonical ∧
      canonical.amount = hrp.amount := by
  have bound : pico < 2^64 := by
    unfold Hrp.picoAmount at available
    cases h : hrp.rawAmount with
    | none => simp [h] at available
    | some n =>
      rw [h] at available
      change (if n.toNat * (hrp.multiplier.map Multiplier.factor).getD 1000000000000 < 2^64
        then some (n.toNat * (hrp.multiplier.map Multiplier.factor).getD 1000000000000)
        else none) = _ at available
      split at available <;> simp_all
  have product : 10 * (pico / 10) = pico := by omega
  obtain ⟨canonical, built, _, _, amount⟩ := hrpFromMsat_exact hrp.currency
    (Bitcoin.Amount.ofMsat (pico / 10)) (by simpa only [Bitcoin.Amount.ofMsat, product] using bound)
  refine ⟨canonical, built, ?_⟩
  simpa only [Hrp.amount, available, Option.map_some] using amount

theorem hrp_amount_absent (hrp : Hrp) (absent : hrp.rawAmount = none) :
    hrp.picoAmount = none ∧ hrp.amount = none ∧ checkPrecision hrp = .ok () := by
  have hp : hrp.picoAmount = none := by simp [Hrp.picoAmount, absent]
  exact ⟨hp, by simp [Hrp.amount, hp], checkPrecision_unavailable hrp hp⟩

private theorem digits_read (n : Nat) :
    (toString n).toList.foldl (fun n c => n * 10 + (c.toNat - '0'.toNat)) 0 = n := by
  simpa only [Nat.toString_eq_ofList_toDigits, String.toList_ofList, Nat.ofDigitChars,
    Nat.mul_comm] using (Nat.ofDigitChars_ten_toDigits (n := n))

private theorem digits_all (n : Nat) : ∀ c ∈ (toString n).toList, c.isDigit = true := by
  intro c hc
  simp only [Nat.toString_eq_ofList_toDigits, String.toList_ofList] at hc
  exact Nat.isDigit_of_mem_toDigits (by decide) (by decide) hc

private theorem digit_properties (c : Char) (digit : c.isDigit = true) :
    (33 ≤ c.toNat ∧ c.toNat ≤ 126) ∧ c.isUpper = false := by
  have h := Char.isDigit_iff_toNat.mp digit
  change 48 ≤ c.toNat ∧ c.toNat ≤ 57 at h
  constructor
  · constructor <;> omega
  · simp only [Char.isUpper, decide_eq_false_iff_not]
    intro upper
    have : 65 ≤ c.toNat ∧ c.toNat ≤ 90 := by
      have lo := UInt32.le_iff_toNat_le.mp upper.1
      have hi := UInt32.le_iff_toNat_le.mp upper.2
      exact ⟨lo, hi⟩
    omega

private theorem digits_length (n : UInt64) : (toString n.toNat).length ≤ 20 := by
  rw [Nat.toString_eq_ofList_toDigits, String.length_ofList]
  apply (Nat.length_toDigits_le_iff (by decide) (by decide)).mpr
  have := n.toNat_lt
  omega

set_option linter.unusedSimpArgs false in
/-- The HRP bounds follow from the five currencies and UInt64 decimal spelling.
No extra HRP hypotheses are needed at the invoice framing theorem. -/
theorem encodeHrp_properties (hrp : Hrp) (text : String)
    (success : encodeHrp hrp = .ok text) :
    text ≠ "" ∧ (∀ c ∈ text.toList, 33 ≤ c.toNat ∧ c.toNat ≤ 126) ∧
      (∀ c ∈ text.toList, c.isUpper = false) ∧ text.length ≤ 83 := by
  unfold encodeHrp at success
  simp only [Bind.bind, Except.bind, Pure.pure, Except.pure] at success
  split at success <;> try contradiction
  split at success <;> try contradiction
  have output := Except.ok.inj success
  change "ln" ++ hrp.currency.text ++ (hrp.rawAmount.map (toString ·.toNat)).getD "" ++
    (hrp.multiplier.map Multiplier.text).getD "" = text at output
  subst text
  have currency : hrp.currency.text ≠ "" ∧ hrp.currency.text.length ≤ 4 ∧
      (∀ c ∈ hrp.currency.text.toList, 33 ≤ c.toNat ∧ c.toNat ≤ 126) ∧
      (∀ c ∈ hrp.currency.text.toList, c.isUpper = false) := by
    cases hrp.currency <;> decide
  have amount : ((hrp.rawAmount.map (toString ·.toNat)).getD "").length ≤ 20 ∧
      (∀ c ∈ ((hrp.rawAmount.map (toString ·.toNat)).getD "").toList,
        (33 ≤ c.toNat ∧ c.toNat ≤ 126) ∧ c.isUpper = false) := by
    cases hrp.rawAmount with
    | none => simp
    | some n => exact ⟨digits_length n, fun c hc => digit_properties c (digits_all n.toNat c hc)⟩
  have unit : ((hrp.multiplier.map Multiplier.text).getD "").length ≤ 1 ∧
      (∀ c ∈ ((hrp.multiplier.map Multiplier.text).getD "").toList,
        (33 ≤ c.toNat ∧ c.toNat ≤ 126) ∧ c.isUpper = false) := by
    cases hrp.multiplier with
    | none => decide
    | some m => cases m <;> decide
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    have hl := congrArg String.length h
    simp only [String.length_append, String.length_empty, show "ln".length = 2 by decide] at hl
    omega
  · intro c hc
    simp only [String.toList_append, List.mem_append] at hc
    rcases hc with ((hc | hc) | hc) | hc
    · simp at hc; rcases hc with rfl | rfl <;> decide
    · exact currency.2.2.1 c hc
    · exact (amount.2 c hc).1
    · exact (unit.2 c hc).1
  · intro c hc
    simp only [String.toList_append, List.mem_append] at hc
    rcases hc with ((hc | hc) | hc) | hc
    · simp at hc; rcases hc with rfl | rfl <;> decide
    · exact currency.2.2.2 c hc
    · exact (amount.2 c hc).2
    · exact (unit.2 c hc).2
  · simp only [String.length_append, show "ln".length = 2 by decide]
    omega

private theorem decimal_not_empty (n : Nat) : (toString n).toList ≠ [] := by
  simpa only [Nat.toString_eq_ofList_toDigits, String.toList_ofList] using
    (Nat.toDigits_ne_nil (n := n) (b := 10))

private theorem decimal_stop (n : Nat) (suffix : List Char) :
    ((toString n).toList ++ suffix).takeWhile (fun c => !c.isDigit) = [] := by
  cases he : (toString n).toList with
  | nil => exact False.elim (decimal_not_empty n he)
  | cons c cs =>
    have digit := digits_all n c (by rw [he]; simp)
    simp [digit]

set_option linter.unusedSimpArgs false in
theorem parseHrp_spelling (currency : Currency) (n : UInt64) (m : Option Multiplier)
    (bound : n.toNat * (m.map Multiplier.factor).getD 1000000000000 < 2^64) :
    parseHrp ("ln" ++ currency.text ++ toString n.toNat ++ (m.map Multiplier.text).getD "") =
      .ok ⟨currency, some n, m⟩ := by
  let suffix := (m.map Multiplier.text).getD ""
  let text := "ln" ++ currency.text ++ toString n.toNat ++ suffix
  have starts : text.startsWith "ln" = true := by
    apply String.startsWith_string_iff.mpr
    simp only [text, String.toList_append, List.append_assoc]
    exact List.prefix_append _ _
  have len : ¬ text.length ≤ 2 := by
    have hc : 0 < currency.text.length := by cases currency <;> decide
    simp only [text, String.length_append, show "ln".length = 2 by decide]
    omega
  have noCurrencyDigits : ∀ c ∈ currency.text.toList, (!c.isDigit) = true := by
    cases currency <;> decide
  have scan : (currency.text.toList ++ (toString n.toNat).toList ++ suffix.toList).takeWhile
      (fun c => !c.isDigit) = currency.text.toList := by
    rw [List.append_assoc, List.takeWhile_append_of_pos noCurrencyDigits,
      decimal_stop, List.append_nil]
  have suffixStop : suffix.toList.takeWhile Char.isDigit = [] := by
    cases m with
    | none => rfl
    | some m => cases m <;> decide
  have digits : ((toString n.toNat).toList ++ suffix.toList).takeWhile Char.isDigit =
      (toString n.toNat).toList := by
    rw [List.takeWhile_append_of_pos (digits_all _), suffixStop, List.append_nil]
  have dropCurrency : (currency.text.toList ++ (toString n.toNat).toList ++ suffix.toList).drop
      currency.text.toList.length = (toString n.toNat).toList ++ suffix.toList := by
    rw [List.append_assoc, List.drop_left]
  have tail : text.toList.drop 2 = currency.text.toList ++ (toString n.toNat).toList ++ suffix.toList := by
    simp only [text, String.toList_append, List.append_assoc]
    rfl
  have rawBound : ¬ n.toNat ≥ 2^64 := by have := n.toNat_lt; omega
  have read : (Nat.toDigits 10 n.toNat).foldl (fun n c => n * 10 + (c.toNat - 48)) 0 = n.toNat := by
    simpa only [Nat.toString_eq_ofList_toDigits, String.toList_ofList,
      show '0'.toNat = 48 by decide] using digits_read n.toNat
  change parseHrp text = _
  unfold parseHrp
  simp only [starts, Bool.not_true, len, Bool.false_or, ↓reduceIte,
    tail, scan, dropCurrency, digits, List.drop_left, String.ofList_toList]
  cases currency <;> cases m with
  | none =>
    simp [suffix, Currency.text, decimal_not_empty, read, rawBound,
      Pure.pure, Except.pure, Bind.bind, Except.bind, UInt64.ofNat_toNat]
      <;> simp_all
  | some m =>
    cases m <;>
      simp [suffix, Currency.text, Multiplier.text, Multiplier.factor, decimal_not_empty,
        read, rawBound,
        Pure.pure, Except.pure, Bind.bind, Except.bind, UInt64.ofNat_toNat]
      <;> simp_all [Multiplier.factor]

/-- Canonical decimal encoding parses to the same structurally representable HRP. -/
theorem parseHrp_encodeHrp (hrp : Hrp) (repr : RepresentableHrp hrp) :
    ∃ text, encodeHrp hrp = .ok text ∧ parseHrp text = .ok hrp := by
  obtain ⟨currency, raw, multiplier⟩ := hrp
  cases raw with
  | none =>
    have hm : multiplier = none := repr
    subst multiplier
    cases currency <;> refine ⟨_, rfl, ?_⟩ <;> cbv
  | some n =>
    change n.toNat * (multiplier.map Multiplier.factor).getD 1000000000000 < 2^64 at repr
    have hp : (Hrp.mk currency (some n) multiplier).picoAmount =
        some (n.toNat * (multiplier.map Multiplier.factor).getD 1000000000000) := by
      change (if n.toNat * (multiplier.map Multiplier.factor).getD 1000000000000 < 2^64
        then some (n.toNat * (multiplier.map Multiplier.factor).getD 1000000000000) else none) = _
      rw [ite_eq_left repr]
    refine ⟨_, ?_, parseHrp_spelling currency n multiplier repr⟩
    simp [encodeHrp, hp, Pure.pure, Except.pure]

/-- The forward amount theorem includes successful canonical HRP parsing. -/
theorem hrpFromMsat_roundTrip (currency : Currency) (a : Bitcoin.Amount)
    (bound : 10 * a.msat < 2^64) :
    ∃ hrp text, hrpFromMsat currency a = .ok hrp ∧ encodeHrp hrp = .ok text ∧
      parseHrp text = .ok hrp ∧ hrp.amount = some a := by
  obtain ⟨hrp, built, _, pico, amount⟩ := hrpFromMsat_exact currency a bound
  have repr : RepresentableHrp hrp := by
    unfold Hrp.picoAmount at pico
    cases h : hrp.rawAmount with
    | none => simp [h] at pico
    | some n =>
      rw [h] at pico
      change (if n.toNat * (hrp.multiplier.map Multiplier.factor).getD 1000000000000 < 2^64
        then some _ else none) = _ at pico
      split at pico
      · simpa only [RepresentableHrp, h] using ‹_ < 2^64›
      · contradiction
  obtain ⟨text, written, parsed⟩ := parseHrp_encodeHrp hrp repr
  exact ⟨hrp, text, built, written, parsed, amount⟩

#print axioms parseHrp_encodeHrp
#print axioms parseHrp_spelling
#print axioms hrpFromMsat_roundTrip
#print axioms encodeHrp_properties
#print axioms checkPrecision_rejects
#print axioms checkPrecision_accepts
#print axioms checkPrecision_unavailable
#print axioms hrpFromMsat_exact
#print axioms hrpFromMsat_overflow
#print axioms hrp_amount_canonical
#print axioms hrp_amount_absent

end Lightning.Bolt11
