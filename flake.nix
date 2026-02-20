{
  description = "Umbra — Kubernetes container diagnostic MCP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    substrate = {
      url = "git+ssh://git@github.com/pleme-io/substrate.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, substrate, ... }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ substrate.overlays.${system}.rust ];
      };

      darwinDeps = pkgs.lib.optionals pkgs.stdenv.isDarwin (
        if pkgs ? apple-sdk
        then [ pkgs.apple-sdk ]
        else pkgs.lib.optionals (pkgs ? darwin) (
          with pkgs.darwin.apple_sdk.frameworks; [
            Security
            SystemConfiguration
          ]
        )
      );

      commonBuildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
        pkgs.libiconv
      ] ++ darwinDeps;

      umbra = pkgs.rustPlatform.buildRustPackage {
        pname = "umbra";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "--package" "umbra" ];

        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = commonBuildInputs;

        meta = with pkgs.lib; {
          description = "Local MCP proxy for Kubernetes container diagnostics";
          homepage = "https://github.com/pleme-io/umbra";
          license = licenses.mit;
          mainProgram = "umbra";
        };
      };

      umbra-agent = pkgs.rustPlatform.buildRustPackage {
        pname = "umbra-agent";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "--package" "umbra-agent" ];

        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = commonBuildInputs;

        meta = with pkgs.lib; {
          description = "Container-side MCP agent for Kubernetes diagnostics";
          homepage = "https://github.com/pleme-io/umbra";
          license = licenses.mit;
          mainProgram = "umbra-agent";
        };
      };
    in {
      packages = {
        default = umbra;
        inherit umbra umbra-agent;
      };

      apps = {
        default = {
          type = "app";
          program = "${umbra}/bin/umbra";
        };
        umbra-agent = {
          type = "app";
          program = "${umbra-agent}/bin/umbra-agent";
        };
      };

      devShells.default = pkgs.mkShell {
        nativeBuildInputs = [
          pkgs.cargo
          pkgs.rustc
          pkgs.pkg-config
        ];
        buildInputs = commonBuildInputs;
        RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
      };
    });
}
