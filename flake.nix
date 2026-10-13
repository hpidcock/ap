{
  description = "ap - unofficial iCloud Keychain client for Linux with an embedded anisette server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        ap = pkgs.callPackage ./nix/package.nix { };
        default = ap;
      });

      apps = forAllSystems (pkgs: rec {
        ap = {
          type = "app";
          program = "${self.packages.${pkgs.system}.ap}/bin/ap";
        };
        default = ap;
      });

      overlays.default = final: prev: {
        ap = final.callPackage ./nix/package.nix { };
      };

      homeManagerModules = rec {
        ap = { config, lib, pkgs, ... }: {
          imports = [ ./nix/hm-module.nix ];
          services.ap.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.ap;
        };
        default = ap;
      };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [ (pkgs.go_1_27 or pkgs.go) pkgs.gopls pkgs.gcc ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
