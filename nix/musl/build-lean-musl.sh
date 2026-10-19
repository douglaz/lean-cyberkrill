#!/usr/bin/env bash
# Build Lean v4.35.0 from source with nixpkgs' pkgsMusl stdenv (dynamic musl), outside the nix sandbox.
# Probe recipe for the Phase 10 static release; the default build uses the official glibc release.
#
# Usage: nix develop .#musl -c nix/musl/build-lean-musl.sh <workdir> [<lean4-source-dir>]
# The source defaults to the pinned v4.35.0 tree, fetched with `nix flake prefetch`.
# The probe build took about 36 minutes.
#
# Not covered here, still needed for a static release (plan.md section 3):
# - prefetch mimalloc, cadical and leantar before CMake tries to download them;
# - rewrite the .so paths baked into the toolchain's link flags as -l flags;
# - a LEAN_CC wrapper whose link line ends in -Wl,-Bstatic.
set -euo pipefail
W=$1
SRC=${2:-$(nix flake prefetch --json \
  github:leanprover/lean4/eb6cafb7290e8bd5f2937522d8d804f58f02bafc \
  | sed -n 's/.*"storePath": *"\([^"]*\)".*/\1/p')}
[ -d "$SRC" ] || { echo "lean4 source not found: $SRC" >&2; exit 1; }
rm -rf "$W/src"; mkdir -p "$W"
cp -r --no-preserve=mode "$SRC" "$W/src"
cd "$W/src"
patchShebangs stage0/src/bin/ src/bin/ script/ >/dev/null 2>&1 || true
chmod +x stage0/src/bin/* src/bin/* 2>/dev/null || true
mkdir -p build/release && cd build/release
echo "CC=$(command -v cc) $(cc -dumpmachine)"
cmake ../.. -DCMAKE_BUILD_TYPE=Release -DUSE_GITHASH=OFF -DSTRIP_BINARIES=OFF -DINSTALL_LICENSE=OFF
time make -j"$(nproc)"
echo BUILD-OK
