{
  description = "A Linux tool that sniffs DNS traffic and dynamically updates nftables sets";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # Systems supported by the package
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      # Helper function to generate outputs for each system
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f rec {
        inherit system;
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      packages = forAllSystems ({ pkgs, system }: {
        default = pkgs.callPackage ./default.nix {};
      });

      devShells = forAllSystems ({ pkgs, system }: {
        default = import ./shell.nix { inherit pkgs; };
      });
    };
}
