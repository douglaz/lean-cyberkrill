{
  description = "lean-cyberkrill: Bitcoin, Lightning and Fedimint libraries for Lean 4, and the cyberkrill CLI";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.lean4-cli = {
    url = "github:leanprover/lean4-cli/c24fe6078c630e89b489bffe59b3e20ac30d12c8";
    flake = false;
  };
  inputs.wycheproof = {
    url = "github:C2SP/wycheproof/7a325932231bd7a724c791c8b0d65ea4d6d2f435";
    flake = false;
  };

  outputs = { self, nixpkgs, wycheproof, lean4-cli }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      # Manual disposable-regtest capture tools; never part of release/check inputs.
      recordingPkgs = import nixpkgs {
        inherit system;
        config = { permittedInsecurePackages = []; allowInsecurePredicate = _: false; };
      };
      cc = pkgs.stdenv.cc;

      # The official Lean v4.35.0 release, patched the way nixpkgs' elan patches toolchains:
      # set the ELF interpreter, and route lake/leanc through nix's cc so linking honours NIX_LDFLAGS.
      # Prepend -L${pkgs.openssl.out}/lib so -lssl -lcrypto resolve to curl's shared nix OpenSSL
      # ahead of the toolchain's static archives (decision B).
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
          exec ${cc}/bin/cc -L${pkgs.openssl.out}/lib "\$@" -L$out/lib
          EOF
          cat > lake <<EOF
          #!${pkgs.runtimeShell}
          LEAN_CC="\''${LEAN_CC:-$out/bin/cc}" exec -a "\$0" $out/bin/lake.orig "\$@"
          EOF
          cat > leanc <<EOF
          #!${pkgs.runtimeShell}
          LEAN_CC="\''${LEAN_CC:-$out/bin/cc}" exec -a "\$0" $out/bin/leanc.orig -L${pkgs.openssl.out}/lib "\$@" -L$out/lib
          EOF
          chmod +x cc lake leanc
          ln -sf ${cc}/bin/ar llvm-ar
        '';
      };

      # Every package, in dependency order; the app comes last.
      lakePackages = [ "sha256" "secp256k1" "bitcoin" "lightning" "fedimint-invite" "http-curl" "cyberkrill" ];

      wycheproofJson = "${wycheproof}/testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json";
      wycheproofDigests = pkgs.runCommand "secp256k1-verify-digests" {
        nativeBuildInputs = [ pkgs.python3 ];
      } ''
        python3 -I - "${wycheproofJson}" "$out" <<'PY'
        import hashlib
        import json
        import sys
        with open(sys.argv[1]) as source, open(sys.argv[2], "w") as output:
            for group in json.load(source)["testGroups"]:
                for test in group["tests"]:
                    digest = hashlib.sha256(bytes.fromhex(test["msg"])).hexdigest()
                    output.write(f"{test['tcId']} {digest}\n")
        PY
      '';

      ffiEnvironment = {
        LEAN4_CLI_DIR = "${lean4-cli}";
        WYCHEPROOF_JSON = wycheproofJson;
        WYCHEPROOF_DER_JSON = "${wycheproof}/testvectors_v1/ecdsa_secp256k1_sha256_test.json";
        WYCHEPROOF_DIGESTS = "${wycheproofDigests}";
        SECP256K1_LIB_DIR = "${pkgs.secp256k1}/lib";
        CURL_LIB_DIR = "${pkgs.curl.out}/lib";
        OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
        OPENSSL_VERSION = pkgs.openssl.version;
      };

      cyberkrill = pkgs.stdenv.mkDerivation (ffiEnvironment // {
        pname = "cyberkrill";
        version = "0.1.0";
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [ ./lean-toolchain ./packages ./scripts ];
        };
        nativeBuildInputs = [ lean pkgs.glibc.bin pkgs.binutils pkgs.python3 pkgs.openssl ];
        buildInputs = [ pkgs.secp256k1 pkgs.curl pkgs.openssl ];
        buildPhase = ''
          export PATH=${pkgs.glibc.getent}/bin:$PATH
          export HOME=$TMPDIR
          mkdir -p packages/cyberkrill/.lake/packages
          cp -r ${lean4-cli} packages/cyberkrill/.lake/packages/Cli
          chmod -R u+w packages/cyberkrill/.lake/packages/Cli
          for p in ${pkgs.lib.concatStringsSep " " lakePackages}; do
            (cd packages/$p && lake build && lake test)
          done
          bash scripts/check-link-spike.sh
        '';
        installPhase = ''
          install -Dm755 packages/cyberkrill/.lake/build/bin/cyberkrill $out/bin/cyberkrill
          $out/bin/cyberkrill version
        '';
      });
    in
    {
      packages.${system} = {
        default = cyberkrill;
        inherit lean;
      };

      checks.${system}.default = cyberkrill;

      devShells.${system} = {
        recordings =
          assert recordingPkgs.bitcoind.version == "31.1";
          assert recordingPkgs.python3Packages.bip32.version == "5.0";
          assert recordingPkgs.python3Packages.mnemonic.version == "0.21";
          recordingPkgs.mkShell {
            packages = [
              (recordingPkgs.python3.withPackages (ps: [ ps.bip32 ps.mnemonic ]))
              recordingPkgs.bitcoind recordingPkgs.curl recordingPkgs.iproute2
              recordingPkgs.util-linux recordingPkgs.coreutils recordingPkgs.gnugrep
              recordingPkgs.glibc.bin recordingPkgs.glibc.getent
            ];
          };
        default = pkgs.mkShell (ffiEnvironment // {
          shellHook = ''
            _cli_root=$(git rev-parse --show-toplevel)
            if [ ! -d "$_cli_root/packages/cyberkrill/.lake/packages/Cli" ]; then
              mkdir -p "$_cli_root/packages/cyberkrill/.lake/packages"
              cp -r ${lean4-cli} "$_cli_root/packages/cyberkrill/.lake/packages/Cli"
              chmod -R u+w "$_cli_root/packages/cyberkrill/.lake/packages/Cli"
            fi
          '';
          packages = [ lean pkgs.glibc.bin pkgs.binutils pkgs.python3 pkgs.openssl ];
          buildInputs = [ pkgs.secp256k1 pkgs.curl pkgs.openssl ];
        });
        # Phase 10 probe: build the Lean toolchain against musl. See nix/musl/build-lean-musl.sh.
        musl = import ./nix/musl/musl-shell.nix { inherit pkgs; };
      };
    };
}
