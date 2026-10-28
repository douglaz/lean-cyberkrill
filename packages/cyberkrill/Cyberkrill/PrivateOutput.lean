/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
namespace Cyberkrill

/-- Atomically create an owner-only new file, write all UTF-8 bytes and check close.
An existing destination leaf is never opened. This does not promise fsync durability. -/
@[extern "lck_write_private_file"]
opaque writePrivateFile (path content : @& String) : IO Unit

end Cyberkrill
