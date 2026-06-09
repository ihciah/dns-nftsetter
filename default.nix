{ pkgs ? import <nixpkgs> {} }:

pkgs.callPackage ({ lib, rustPlatform, pkg-config, libpcap }:
rustPlatform.buildRustPackage {
  pname = "dns-nftsetter";
  version = "0.1.0";

  src = ./.;

  cargoHash = "sha256-Y8w1JcqbmgTcBqg0yVVXfS5oRGSjhMxUQ0C0U9iEV1w=";

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ libpcap ];

  meta = with lib; {
    description = "A Linux tool that sniffs DNS traffic and dynamically updates nftables sets";
    homepage = "https://github.com/ihciah/dns-nftsetter";
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux ++ platforms.darwin;
  };
}) {}
