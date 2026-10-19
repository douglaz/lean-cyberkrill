# Shell for the musl toolchain probe (plan.md section 3, "Static musl release task").
# Entered through the flake so nixpkgs stays pinned by flake.lock: `nix develop .#musl`.
{ pkgs }:
let
  p = pkgs.pkgsMusl;
in
p.mkShell {
  nativeBuildInputs = [ pkgs.cmake pkgs.git pkgs.perl p.buildPackages.pkg-config ];
  buildInputs = [ p.gmp p.libuv p.openssl ];
  hardeningDisable = [ "all" ];
}
