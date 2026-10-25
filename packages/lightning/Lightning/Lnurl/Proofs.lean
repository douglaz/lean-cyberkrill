/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin.Bech32Codec

namespace Lightning.Lnurl

/-- Codec corollary, not a public LNURL URL encoder. The only premise is length. -/
theorem bech32_roundTrip (data : List Bitcoin.Bech32.Symbol) (v : Bitcoin.Bech32.Variant)
    (fits : 5 + data.length + 7 ≤ 1023) :
    Bitcoin.Bech32.decode 1023 (Bitcoin.Bech32.encode "lnurl" data v) =
      .ok ("lnurl", data, v) := by
  apply Bitcoin.Bech32.decode_encode
  · decide
  · decide
  · decide
  · decide
  · exact fits

/-- Success certifies the six checksum symbols actually present in the source. -/
theorem bech32_checksumSound (s : String) (data : List Bitcoin.Bech32.Symbol)
    (v : Bitcoin.Bech32.Variant)
    (success : Bitcoin.Bech32.decode 1023 s = .ok ("lnurl", data, v)) :
    ∃ chk : List Bitcoin.Bech32.Symbol, chk.length = 6 ∧
      Bitcoin.Bech32.lower s = "lnurl" ++ "1" ++
        String.ofList ((data ++ chk).map Bitcoin.Bech32.charOf) ∧
      Bitcoin.Bech32.verifyChecksum v "lnurl" (data ++ chk) = true :=
  Bitcoin.Bech32.decode_sound 1023 s "lnurl" data v success

#print axioms bech32_roundTrip
#print axioms bech32_checksumSound

end Lightning.Lnurl
