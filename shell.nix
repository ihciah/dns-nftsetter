{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.pkg-config
  ];

  buildInputs = [
    pkgs.cargo
    pkgs.rustc
    pkgs.libpcap
  ];

  shellHook = ''
    export RUST_BACKTRACE=1
  '';
}
