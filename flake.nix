{
  description = "lean-cyberkrill: Bitcoin, Lightning and Fedimint libraries for Lean 4, and the cyberkrill CLI";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      cc = pkgs.stdenv.cc;

      # The official Lean v4.35.0 release, patched the way nixpkgs' elan patches toolchains:
      # set the ELF interpreter, and route lake/leanc through nix's cc so linking honours NIX_LDFLAGS.
      lean = pkgs.stdenv.mkDerivation {
        pname = "lean4-bin";
        version = "4.35.0";
        src = pkgs.fetchurl {
          url = "https://github.com/leanprover/lean4/releases/download/v4.35.0/lean-4.35.0-linux.tar.zst";
          hash = "sha256-colZekRUMkbJInuMrlAXZ+CVzhf21Ei5X8So3Jcmj20=";
        };
        nativeBuildInputs = [ pkgs.zstd pkgs.patchelf ];
        dontConfigure = true;
        dontBuild = true;
        dontStrip = true;
        dontPatchELF = true;
        installPhase = ''
          mkdir -p $out
          cp -r . $out
          cd $out/bin
          for f in *; do
            # Skip scripts and statically linked binaries (no interpreter to replace).
            if patchelf --print-interpreter "$f" >/dev/null 2>&1; then
              patchelf --set-interpreter "$(cat ${cc}/nix-support/dynamic-linker)" "$f"
            fi
          done
          mv lake lake.orig
          mv leanc leanc.orig
          cat > cc <<EOF
          #!${pkgs.runtimeShell}
          exec ${cc}/bin/cc "\$@" -L$out/lib
          EOF
          cat > lake <<EOF
          #!${pkgs.runtimeShell}
          LEAN_CC="\''${LEAN_CC:-$out/bin/cc}" exec -a "\$0" $out/bin/lake.orig "\$@"
          EOF
          cat > leanc <<EOF
          #!${pkgs.runtimeShell}
          LEAN_CC="\''${LEAN_CC:-${cc}/bin/cc}" exec -a "\$0" $out/bin/leanc.orig "\$@" -L$out/lib
          EOF
          chmod +x cc lake leanc
          ln -sf ${cc}/bin/ar llvm-ar
        '';
      };

      # Every package, in dependency order; the app comes last.
      lakePackages = [ "sha256" "secp256k1" "bitcoin" "lightning" "fedimint-invite" "http-curl" "cyberkrill" ];

      cyberkrill = pkgs.stdenv.mkDerivation {
        pname = "cyberkrill";
        version = "0.1.0";
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [ ./lean-toolchain ./packages ];
        };
        nativeBuildInputs = [ lean ];
        buildPhase = ''
          export HOME=$TMPDIR
          for p in ${pkgs.lib.concatStringsSep " " lakePackages}; do
            (cd packages/$p && lake build && lake test)
          done
        '';
        installPhase = ''
          install -Dm755 packages/cyberkrill/.lake/build/bin/cyberkrill $out/bin/cyberkrill
          $out/bin/cyberkrill
        '';
      };
    in
    {
      packages.${system} = {
        default = cyberkrill;
        inherit lean;
      };

      checks.${system}.default = cyberkrill;

      devShells.${system} = {
        default = pkgs.mkShell { packages = [ lean ]; };
        # Phase 10 probe: build the Lean toolchain against musl. See nix/musl/build-lean-musl.sh.
        musl = import ./nix/musl/musl-shell.nix { inherit pkgs; };
      };
    };
}
