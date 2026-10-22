-- Copied from febyeji/lean-miniscript @ cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd, LeanMiniscript/Script/Syntax.lean L1-2; MIT, see LICENSE-miniscript
instance : Repr ByteArray where
  reprPrec ba _ := s!"ByteArray#{repr ba.data}"
