/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Lightning.Bolt11.Types

namespace Lightning.Bolt11

def readNat (symbols : List Symbol) : Nat :=
  symbols.foldl (fun acc word => acc * 32 + word.toNat) 0

def writeNat (value : Nat) : List Symbol :=
  if value = 0 then [] else writeNat (value / 32) ++ [BitVec.ofNat 5 value]
termination_by value
decreasing_by omega

def readBytes (bytes : ByteArray) : Nat :=
  bytes.data.foldl (fun acc byte => acc * 256 + byte.toNat) 0

def writeBytes (width value : Nat) : ByteArray :=
  ⟨(List.range width |>.map fun i => UInt8.ofNat (value / 256^(width - 1 - i))).toArray⟩

private def strictBytes (tag : Symbol) (data : List Symbol) : Except Error ByteArray :=
  (Bitcoin.Bech32.convertbits5to8 data).mapError fun _ => .nonCanonicalPadding tag

def decodeHop (cap : Curve) (bytes : ByteArray) : Except Error RouteHop := do
  let key := bytes.extract 0 33
  if !cap.isValidPubkey key then throw (.malformedField 3)
  return { nodeId := key
           shortChannelId := UInt64.ofNat (readBytes (bytes.extract 33 41))
           feeBaseMsat := UInt32.ofNat (readBytes (bytes.extract 41 45))
           feeProportionalMillionths := UInt32.ofNat (readBytes (bytes.extract 45 49))
           cltvExpiryDelta := UInt16.ofNat (readBytes (bytes.extract 49 51)) }

def encodeHop (hop : RouteHop) : ByteArray :=
  hop.nodeId ++ writeBytes 8 hop.shortChannelId.toNat ++ writeBytes 4 hop.feeBaseMsat.toNat ++
    writeBytes 4 hop.feeProportionalMillionths.toNat ++ writeBytes 2 hop.cltvExpiryDelta.toNat

private def integer (tag : Symbol) (data : List Symbol) : Except Error UInt64 := do
  if data.head? = some 0 then throw (.leadingZero tag)
  let value := readNat data
  if value ≥ 2^64 then throw (.malformedField tag)
  return UInt64.ofNat value

/-- Decode one field without semantic counts, feature requirements or signatures. -/
def decodeField (cap : Curve) (tag : Symbol) (data : List Symbol) : Except Error Field := do
  match tag.toNat with
  | 1 | 23 | 16 | 19 =>
    let expected := if tag.toNat = 19 then 53 else 52
    if data.length ≠ expected then return .raw tag data
    let bytes ← strictBytes tag data
    match tag.toNat with
    | 1 => return .paymentHash bytes
    | 23 => return .descriptionHash bytes
    | 16 => return .paymentSecret bytes
    | _ =>
      if !cap.isValidPubkey bytes then throw (.malformedField tag)
      return .payeePubkey bytes
  | 13 =>
    let bytes ← strictBytes tag data
    let some text := String.fromUTF8? bytes | throw (.malformedField tag)
    return .description text
  | 27 => return .metadata (← strictBytes tag data)
  | 6 => return .expiry (← integer 6 data)
  | 24 => return .minFinalCltvExpiryDelta (← integer 24 data)
  | 5 =>
    if data.head? = some 0 then throw (.leadingZero 5)
    return .features (readNat data)
  | 9 =>
    let version :: program := data | throw (.malformedField tag)
    if version.toNat > 18 then return .raw tag data
    let bytes ← strictBytes tag program
    if h : version.toNat < 17 then
      if bytes.size < 2 || bytes.size > 40 then throw (.malformedField tag)
      return .fallback (.segwit ⟨version.toNat, h⟩ bytes)
    else
      if bytes.size ≠ 20 then throw (.malformedField tag)
      return .fallback (if version.toNat = 17 then .p2pkh bytes else .p2sh bytes)
  | 3 =>
    let bytes ← strictBytes tag data
    if bytes.size % 51 ≠ 0 then throw (.malformedField tag)
    return .route (← (List.range (bytes.size / 51)).mapM fun i =>
      decodeHop cap (bytes.extract (i * 51) ((i + 1) * 51)))
  | _ => return .raw tag data

/-- Raw field framing and typing only; the curve capability validates typed node ids. -/
def decodeFields (cap : Curve) (symbols : List Symbol) : Except Error (List Field) := do
  match symbols with
  | [] => return []
  | tag :: hi :: lo :: rest =>
    let len := hi.toNat * 32 + lo.toNat
    if rest.length < len then throw .unexpectedEndOfTaggedFields
    let field ← decodeField cap tag (rest.take len)
    return field :: (← decodeFields cap (rest.drop len))
  | _ => throw .unexpectedEndOfTaggedFields
termination_by symbols.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

/-- Canonical field data; raw fields retain their exact symbols. -/
def fieldData : Field → List Symbol
  | .paymentHash b | .descriptionHash b | .paymentSecret b | .payeePubkey b | .metadata b =>
    Bitcoin.Bech32.convertbits8to5 b
  | .description text => Bitcoin.Bech32.convertbits8to5 text.toUTF8
  | .expiry n | .minFinalCltvExpiryDelta n => writeNat n.toNat
  | .features n => writeNat n
  | .fallback (.segwit version program) =>
    BitVec.ofNat 5 version.val :: Bitcoin.Bech32.convertbits8to5 program
  | .fallback (.p2pkh hash) => 17 :: Bitcoin.Bech32.convertbits8to5 hash
  | .fallback (.p2sh hash) => 18 :: Bitcoin.Bech32.convertbits8to5 hash
  | .route hops => Bitcoin.Bech32.convertbits8to5
    (hops.foldl (fun bytes hop => bytes ++ encodeHop hop) ByteArray.empty)
  | .raw _ data => data

/-- Whether `decodeField` keeps these symbols raw under this tag: an unknown tag, a
wrong-length `p`/`h`/`s`/`n`, or a fallback version above 18. -/
def staysRaw (tag : Symbol) (data : List Symbol) : Bool :=
  match tag.toNat with
  | 1 | 23 | 16 => data.length != 52
  | 19 => data.length != 53
  | 9 => match data with | version :: _ => version.toNat > 18 | [] => false
  | 3 | 5 | 6 | 13 | 24 | 27 => false
  | _ => true

def validFieldShape : Field → Bool
  | .paymentHash b | .descriptionHash b | .paymentSecret b => b.size == 32
  | .payeePubkey b => b.size == 33
  | .fallback (.segwit _ b) => 2 ≤ b.size && b.size ≤ 40
  | .fallback (.p2pkh b) | .fallback (.p2sh b) => b.size == 20
  | .route hops => hops.all fun hop => hop.nodeId.size == 33
  | .raw tag data => staysRaw tag data
  | _ => true

/-- Write canonical field data and 10-bit lengths, with raw fields verbatim.
The invoice encoder checks field shapes and length bounds separately. -/
def encodeFields (fields : List Field) : List Symbol :=
  fields.flatMap fun field =>
    let data := fieldData field
    [field.tag, BitVec.ofNat 5 (data.length / 32), BitVec.ofNat 5 data.length] ++ data

theorem readNat_append (xs ys : List Symbol) (acc : Nat) :
    (xs ++ ys).foldl (fun n x => n * 32 + x.toNat) acc =
      ys.foldl (fun n x => n * 32 + x.toNat)
        (xs.foldl (fun n x => n * 32 + x.toNat) acc) := List.foldl_append

theorem readNat_writeNat (n : Nat) : readNat (writeNat n) = n := by
  rw [writeNat]
  split
  · subst n; rfl
  · simp only [readNat, List.foldl_append, List.foldl_cons, List.foldl_nil]
    change readNat (writeNat (n / 32)) * 32 + n % 32 = n
    rw [readNat_writeNat (n / 32)]
    omega
termination_by n
decreasing_by omega

theorem writeNat_head (n : Nat) : (writeNat n).head? ≠ some 0 := by
  rw [writeNat]
  split
  · simp
  · rename_i hn
    by_cases small : n / 32 = 0
    · simp only [small, writeNat, ↓reduceIte, List.nil_append, List.head?_cons,
        Option.some.injEq, ne_eq]
      intro h
      have he := congrArg BitVec.toNat h
      change n % 32 = 0 at he
      omega
    · have ne : writeNat (n / 32) ≠ [] := by
        intro h
        have := readNat_writeNat (n / 32)
        rw [h] at this
        simp [readNat] at this
        exact small this.symm
      have ih := writeNat_head (n / 32)
      cases he : writeNat (n / 32) with
      | nil => exact False.elim (ne he)
      | cons x xs => simpa only [he, List.cons_append, List.head?_cons] using ih
termination_by n
decreasing_by omega

set_option linter.unusedSimpArgs false in
theorem integer_writeNat (tag : Symbol) (n : UInt64) :
    integer tag (writeNat n.toNat) = .ok n := by
  have bound : ¬ n.toNat ≥ 2^64 := by have := n.toNat_lt; omega
  have head := writeNat_head n.toNat
  simp only [integer, head, and_false, ↓reduceIte, readNat_writeNat, bound,
    UInt64.ofNat_toNat]
  rfl

theorem strictBytes_encode (tag : Symbol) (bytes : ByteArray) :
    strictBytes tag (Bitcoin.Bech32.convertbits8to5 bytes) = .ok bytes := by
  unfold strictBytes
  first
  | rw [Bitcoin.Bech32.convertbits5to8_convertbits8to5]; rfl
  | rw [Bitcoin.Bech32.fesToBytesLax_convertbits8to5]

theorem string_utf8_roundTrip (s : String) : String.fromUTF8? s.toUTF8 = some s := by
  simp only [String.toUTF8_eq_toByteArray, String.fromUTF8?]
  simp only [dite_eq_left s.isValidUTF8]
  rfl

/-- Structural raw cases. An empty fallback is a hard error, not a raw field. -/
def KeptRaw (tag : Symbol) (data : List Symbol) : Prop :=
  match tag.toNat with
  | 1 | 23 | 16 => data.length ≠ 52
  | 19 => data.length ≠ 53
  | 9 => ∃ version rest, data = version :: rest ∧ 18 < version.toNat
  | 3 | 5 | 6 | 13 | 24 | 27 => False
  | _ => True

theorem keptRaw_iff_staysRaw (tag : Symbol) (data : List Symbol) :
    KeptRaw tag data ↔ staysRaw tag data = true := by
  unfold KeptRaw staysRaw
  split <;> try simp
  cases data <;> simp

theorem decodeField_keptRaw (cap : Curve) (tag : Symbol) (data : List Symbol)
    (kept : KeptRaw tag data) : decodeField cap tag data = .ok (.raw tag data) := by
  unfold KeptRaw at kept
  unfold decodeField
  split <;> simp_all <;> try rfl
  obtain ⟨v, ⟨rest, rfl⟩, hv⟩ := kept
  simp only [hv, ↓reduceIte]
  rfl

theorem writeBytes_size (width n : Nat) : (writeBytes width n).size = width := by
  simp [writeBytes, ByteArray.size]

theorem writeBytes_succ (width n : Nat) :
    writeBytes (width + 1) n = writeBytes width (n / 256) ++
      ⟨#[UInt8.ofNat n]⟩ := by
  apply ByteArray.ext
  apply Array.toList_inj.mp
  simp only [writeBytes, ByteArray.data_append, List.range_succ, List.map_append,
    List.map_cons, List.map_nil, Array.toList_append, List.toList_toArray,
    Nat.add_sub_cancel, Nat.sub_self, Nat.pow_zero, Nat.div_one]
  congr 1
  apply List.map_congr_left
  intro i hi
  have bound := List.mem_range.mp hi
  have exponent : width - i = (width - 1 - i) + 1 := by omega
  rw [exponent, Nat.pow_succ, Nat.div_div_eq_div_mul, Nat.mul_comm 256]

theorem readBytes_writeBytes (width n : Nat) (bound : n < 256^width) :
    readBytes (writeBytes width n) = n := by
  induction width generalizing n with
  | zero =>
    have : n = 0 := by simpa using bound
    subst n; rfl
  | succ width ih =>
    rw [writeBytes_succ]
    have smaller : n / 256 < 256^width := by
      rw [Nat.pow_succ] at bound
      omega
    simp only [readBytes, ByteArray.data_append, Array.foldl_append]
    change readBytes (writeBytes width (n / 256)) * 256 + n % 256 = n
    rw [ih _ smaller]
    omega

theorem encodeHop_size (hop : RouteHop) (shape : hop.nodeId.size = 33) :
    (encodeHop hop).size = 51 := by
  simp [encodeHop, ByteArray.size_append, writeBytes_size, shape]

theorem decodeHop_encodeHop (cap : Curve) (hop : RouteHop)
    (shape : hop.nodeId.size = 33) (point : cap.isValidPubkey hop.nodeId = true) :
    decodeHop cap (encodeHop hop) = .ok hop := by
  have whole (w n : Nat) : (writeBytes w n).extract 0 w = writeBytes w n := by
    simpa only [writeBytes_size] using (ByteArray.extract_zero_size (b := writeBytes w n))
  have past (b : ByteArray) (i j : Nat) (hi : b.size ≤ i) :
      b.extract i j = ByteArray.empty := ByteArray.extract_eq_empty_iff.mpr (by omega)
  have wholeKey : hop.nodeId.extract 0 33 = hop.nodeId := by
    simpa only [shape] using (ByteArray.extract_zero_size (b := hop.nodeId))
  have key : (encodeHop hop).extract 0 33 = hop.nodeId := by
    simp [encodeHop, ByteArray.extract_append, ByteArray.size_append, writeBytes_size, shape,
      wholeKey]
  have channel : (encodeHop hop).extract 33 41 = writeBytes 8 hop.shortChannelId.toNat := by
    simp [encodeHop, ByteArray.extract_append, ByteArray.size_append, writeBytes_size, shape,
      whole, past]
  have base : (encodeHop hop).extract 41 45 = writeBytes 4 hop.feeBaseMsat.toNat := by
    simp [encodeHop, ByteArray.extract_append, ByteArray.size_append, writeBytes_size, shape,
      whole, past]
  have proportional : (encodeHop hop).extract 45 49 =
      writeBytes 4 hop.feeProportionalMillionths.toNat := by
    simp [encodeHop, ByteArray.extract_append, ByteArray.size_append, writeBytes_size, shape,
      whole, past]
  have delta : (encodeHop hop).extract 49 51 = writeBytes 2 hop.cltvExpiryDelta.toNat := by
    simp [encodeHop, ByteArray.extract_append, ByteArray.size_append, writeBytes_size, shape,
      whole, past]
  have h64 : hop.shortChannelId.toNat < 256^8 := hop.shortChannelId.toNat_lt
  have h32a : hop.feeBaseMsat.toNat < 256^4 := hop.feeBaseMsat.toNat_lt
  have h32b : hop.feeProportionalMillionths.toNat < 256^4 := hop.feeProportionalMillionths.toNat_lt
  have h16 : hop.cltvExpiryDelta.toNat < 256^2 := hop.cltvExpiryDelta.toNat_lt
  simp only [decodeHop, key, point, Bool.not_true, Bool.false_eq_true, ↓reduceIte,
    channel, base, proportional, delta, readBytes_writeBytes _ _ h64,
    readBytes_writeBytes _ _ h32a, readBytes_writeBytes _ _ h32b,
    readBytes_writeBytes _ _ h16, UInt64.ofNat_toNat, UInt32.ofNat_toNat, UInt16.ofNat_toNat]
  rfl

private def hopBytes : List RouteHop → ByteArray
  | [] => ByteArray.empty
  | hop :: hops => encodeHop hop ++ hopBytes hops

private theorem hopBytes_foldl (hops : List RouteHop) (acc : ByteArray) :
    hops.foldl (fun bytes hop => bytes ++ encodeHop hop) acc = acc ++ hopBytes hops := by
  induction hops generalizing acc with
  | nil => simp [hopBytes]
  | cons hop hops ih => simp [hopBytes, ih, ByteArray.append_assoc]

private theorem hopBytes_size (hops : List RouteHop)
    (shapes : ∀ hop ∈ hops, hop.nodeId.size = 33) : (hopBytes hops).size = hops.length * 51 := by
  induction hops with
  | nil => rfl
  | cons hop hops ih =>
    simp only [hopBytes, ByteArray.size_append, List.length_cons]
    rw [encodeHop_size hop (shapes hop (by simp)),
      ih (fun h hh => shapes h (by simp [hh]))]
    omega

private theorem hopBytes_extract (hop : RouteHop) (hops : List RouteHop) (i : Nat)
    (shapes : ∀ h ∈ hop :: hops, h.nodeId.size = 33) :
    (hopBytes (hop :: hops)).extract ((i + 1) * 51) ((i + 1 + 1) * 51) =
      (hopBytes hops).extract (i * 51) ((i + 1) * 51) := by
  change (encodeHop hop ++ hopBytes hops).extract _ _ = _
  rw [ByteArray.extract_append]
  have size := encodeHop_size hop (shapes hop (by simp))
  have sub1 : (i + 1) * 51 - (encodeHop hop).size = i * 51 := by
    rw [size]; clear shapes size hop hops; omega
  have sub2 : (i + 1 + 1) * 51 - (encodeHop hop).size = (i + 1) * 51 := by
    rw [size]; clear sub1 shapes size hop hops; omega
  rw [ByteArray.extract_eq_empty_iff.mpr (by
      rw [size]; clear sub1 sub2 shapes size hop hops; omega),
    ByteArray.empty_append, sub1, sub2]

theorem route_roundTrip (cap : Curve) (hops : List RouteHop)
    (shapes : ∀ hop ∈ hops, hop.nodeId.size = 33)
    (points : ∀ hop ∈ hops, cap.isValidPubkey hop.nodeId = true) :
    (List.range ((hopBytes hops).size / 51)).mapM (fun i =>
      decodeHop cap ((hopBytes hops).extract (i * 51) ((i + 1) * 51))) = .ok hops := by
  rw [hopBytes_size hops shapes, Nat.mul_div_cancel _ (by decide)]
  induction hops with
  | nil => rfl
  | cons hop hops ih =>
    rw [List.length_cons, List.range_succ_eq_map, List.mapM_cons, List.mapM_map]
    have first : (hopBytes (hop :: hops)).extract 0 51 = encodeHop hop := by
      change (encodeHop hop ++ hopBytes hops).extract 0 51 = _
      rw [ByteArray.extract_append_eq_left (encodeHop_size hop (shapes hop (by simp))).symm]
    simp only [Nat.zero_mul, Nat.zero_add, Nat.one_mul, first,
      decodeHop_encodeHop cap hop (shapes hop (by simp)) (points hop (by simp)),
      Function.comp_def, hopBytes_extract hop hops _ shapes]
    rw [ih (fun h hh => shapes h (by simp [hh])) (fun h hh => points h (by simp [hh]))]
    rfl

/-- Representation, independently inspectable without executing the field decoder.
Integer constructors carry UInt64 values; strings carry validated UTF-8; feature
bitsets have no semantic restriction. The framing bound applies to every constructor. -/
def RepresentableField (cap : Curve) (field : Field) : Prop :=
  (fieldData field).length < 1024 ∧ match field with
  | .paymentHash b | .descriptionHash b | .paymentSecret b => b.size = 32
  | .payeePubkey b => b.size = 33 ∧ cap.isValidPubkey b = true
  | .fallback (.segwit _ b) => 2 ≤ b.size ∧ b.size ≤ 40
  | .fallback (.p2pkh b) | .fallback (.p2sh b) => b.size = 20
  | .route hops => ∀ hop ∈ hops, hop.nodeId.size = 33 ∧ cap.isValidPubkey hop.nodeId = true
  | .raw tag data => KeptRaw tag data
  | _ => True

set_option linter.unusedSimpArgs false in
theorem decodeField_fieldData (cap : Curve) (field : Field)
    (repr : RepresentableField cap field) :
    decodeField cap field.tag (fieldData field) = .ok field := by
  obtain ⟨_, shape⟩ := repr
  cases field with
  | paymentHash b | descriptionHash b | paymentSecret b =>
    simp [Field.tag, fieldData, decodeField, Bitcoin.Bech32.convertbits8to5_length_exact,
      shape, strictBytes_encode, Pure.pure, Except.pure, Functor.map, Except.map]
    rfl
  | payeePubkey b =>
    obtain ⟨size, point⟩ := shape
    simp [Field.tag, fieldData, decodeField, Bitcoin.Bech32.convertbits8to5_length_exact,
      size, point, strictBytes_encode, Pure.pure, Except.pure, Bind.bind, Except.bind,
      Functor.map, Except.map]
  | description s =>
    have utf8 := string_utf8_roundTrip s
    simp only [String.toUTF8_eq_toByteArray] at utf8
    simp [Field.tag, fieldData, decodeField, strictBytes_encode,
      utf8, Pure.pure, Except.pure, Bind.bind, Except.bind]
  | metadata b => simp [Field.tag, fieldData, decodeField, strictBytes_encode,
      Pure.pure, Except.pure, Functor.map, Except.map]
                  rfl
  | expiry n | minFinalCltvExpiryDelta n =>
    simp [Field.tag, fieldData, decodeField, integer_writeNat,
      Pure.pure, Except.pure, Functor.map, Except.map]
    rfl
  | features n =>
    simp only [Field.tag, fieldData, decodeField, BitVec.toNat_ofNat,
      ite_eq_right (writeNat_head n), readNat_writeNat]
    rfl
  | raw tag data => exact decodeField_keptRaw cap tag data shape
  | fallback f =>
    cases f with
    | segwit v b =>
      have hv := v.isLt
      have hv32 : v.val % 32 = v.val := Nat.mod_eq_of_lt (by omega)
      simp [Field.tag, fieldData, decodeField, BitVec.toNat_ofNat, hv32,
        show ¬ 18 < v.val by omega, hv, strictBytes_encode,
        show ¬ b.size < 2 by omega, show ¬ 40 < b.size by omega,
        Pure.pure, Except.pure, Bind.bind, Except.bind, Functor.map, Except.map]
    | p2pkh b | p2sh b =>
      simp [Field.tag, fieldData, decodeField, strictBytes_encode, shape,
        Pure.pure, Except.pure, Bind.bind, Except.bind, Functor.map, Except.map]
  | route hops =>
    have shapes := fun h hh => (shape h hh).1
    have points := fun h hh => (shape h hh).2
    have length := hopBytes_size hops shapes
    have route := route_roundTrip cap hops shapes points
    rw [length, Nat.mul_div_cancel _ (by decide)] at route
    simp only [Field.tag, fieldData, hopBytes_foldl, ByteArray.empty_append]
    simp [decodeField, strictBytes_encode, length, route,
      Pure.pure, Except.pure, Bind.bind, Except.bind, Functor.map, Except.map]

/-- Tagged-field round-trip before invoice counts, feature semantics or signatures. -/
theorem decodeFields_encodeFields (cap : Curve) (fields : List Field)
    (repr : ∀ field ∈ fields, RepresentableField cap field) :
    decodeFields cap (encodeFields fields) = .ok fields := by
  induction fields with
  | nil => rw [encodeFields, List.flatMap_nil, decodeFields]; rfl
  | cons field fields ih =>
    have hf := repr field (by simp)
    have bound := hf.1
    have frame : (BitVec.ofNat 5 ((fieldData field).length / 32)).toNat * 32 +
        (BitVec.ofNat 5 (fieldData field).length).toNat = (fieldData field).length := by
      simp only [BitVec.toNat_ofNat]
      omega
    simp only [encodeFields, List.flatMap_cons, List.cons_append, List.nil_append,
      ]
    rw [decodeFields]
    simp only [frame, List.length_append]
    rw [ite_eq_right (by omega), List.take_left, List.drop_left,
      decodeField_fieldData cap field hf]
    change (do pure (field :: (← decodeFields cap (encodeFields fields)))) = _
    rw [ih (fun f h => repr f (by simp [h]))]
    rfl

#print axioms readNat_writeNat
#print axioms writeNat_head
#print axioms integer_writeNat
#print axioms strictBytes_encode
#print axioms string_utf8_roundTrip
#print axioms keptRaw_iff_staysRaw
#print axioms decodeField_keptRaw
#print axioms readBytes_writeBytes
#print axioms decodeHop_encodeHop
#print axioms route_roundTrip
#print axioms decodeField_fieldData
#print axioms decodeFields_encodeFields

#print axioms readNat_append
#print axioms writeBytes_size
#print axioms writeBytes_succ
#print axioms encodeHop_size

end Lightning.Bolt11
