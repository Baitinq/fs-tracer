{
  description = "FS Tracer Devshell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      with pkgs;
      {
        devShells.default = mkShell {
          buildInputs = [
            rust-analyzer
            openssl
            pkg-config
            (rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-gnu" "wasm32-unknown-unknown" ];
            })
            trunk
	    bpftools
	    bpftrace
	    llvmPackages_17.libclang.lib
          ];
	  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages_17.libclang.lib}/lib"
  '';
        };
      }
    );
}
