{
  description = "Umbra — Kubernetes container diagnostic MCP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };
  };

  outputs = { nixpkgs, flake-utils, substrate, ... }: let
    linuxSystems = ["x86_64-linux" "aarch64-linux"];
    allSystems = linuxSystems ++ ["x86_64-darwin" "aarch64-darwin"];
    forEach = systems: f: nixpkgs.lib.genAttrs systems f;

    registry = "ghcr.io/pleme-io/umbra-agent";

    mkPkgs = system: import nixpkgs {
      inherit system;
      overlays = [ substrate.rustOverlays.${system}.rust ];
    };

    # Substrate lib for release helpers (instantiated per host system)
    mkSubstrateLib = system: import "${substrate}/lib" {
      pkgs = mkPkgs system;
    };

    darwinBuildInputs = pkgs: (import "${substrate}/lib/darwin.nix").mkDarwinBuildInputs pkgs;

    mkUmbra = pkgs: pkgs.rustPlatform.buildRustPackage {
      pname = "umbra";
      version = "0.1.0";
      src = ./.;
      cargoLock.lockFile = ./Cargo.lock;
      cargoBuildFlags = [ "--package" "umbra" ];
      nativeBuildInputs = [ pkgs.pkg-config ];
      buildInputs = darwinBuildInputs pkgs;
      meta = with pkgs.lib; {
        description = "Local MCP proxy for Kubernetes container diagnostics";
        homepage = "https://github.com/pleme-io/umbra";
        license = licenses.mit;
        mainProgram = "umbra";
      };
    };

    mkUmbraAgent = pkgs: pkgs.rustPlatform.buildRustPackage {
      pname = "umbra-agent";
      version = "0.1.0";
      src = ./.;
      cargoLock.lockFile = ./Cargo.lock;
      cargoBuildFlags = [ "--package" "umbra-agent" ];
      nativeBuildInputs = [ pkgs.pkg-config ];
      buildInputs = darwinBuildInputs pkgs;
      meta = with pkgs.lib; {
        description = "Container-side MCP agent for Kubernetes diagnostics";
        homepage = "https://github.com/pleme-io/umbra";
        license = licenses.mit;
        mainProgram = "umbra-agent";
      };
    };

    # OCI container image: umbra-agent + all tool binaries it wraps
    mkImage = system: let
      pkgs = mkPkgs system;
      agent = mkUmbraAgent pkgs;
    in pkgs.dockerTools.buildLayeredImage {
      name = registry;
      tag = "latest";

      contents = [agent] ++ (with pkgs; [
        # --- Base POSIX ---
        bashInteractive
        coreutils
        cacert
        pkgs.dockerTools.fakeNss

        # --- Network diagnostics (Tier 1) ---
        curl
        dnsutils        # dig, nslookup, host
        netcat-openbsd  # nc
        nmap
        tcpdump
        iproute2        # ip, ss
        iputils         # ping, tracepath
        socat
        traceroute

        # --- Process debugging (Tier 2) ---
        strace
        lsof
        procps          # ps, top

        # --- Service clients (Tier 3) ---
        postgresql_16   # psql
        redis           # redis-cli
        grpcurl
        websocat

        # --- Security scanning (Tier 4) ---
        rustscan
        feroxbuster
        testssl
        nuclei
        noseyparker
        jwt-cli
        oha
        legba
        trivy
        httpx

        # --- Data processing ---
        jq
        yq-go
      ]);

      extraCommands = ''
        mkdir -p root tmp
        chmod 1777 tmp
        mkdir -p bin usr/bin
        ln -sf ${pkgs.bashInteractive}/bin/bash bin/bash
        ln -sf ${pkgs.bashInteractive}/bin/bash bin/sh
        ln -sf ${pkgs.coreutils}/bin/env usr/bin/env
      '';

      config = {
        Cmd = [ "${agent}/bin/umbra-agent" ];
        WorkingDir = "/root";
        Env = [
          "HOME=/root"
          "USER=root"
          "TERM=xterm-256color"
          "LANG=C.UTF-8"
          "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        ];
        Labels = {
          "org.opencontainers.image.source" = "https://github.com/pleme-io/umbra";
          "org.opencontainers.image.description" = "Umbra agent — Kubernetes container diagnostics + security scanning (44 MCP tools)";
          "org.opencontainers.image.licenses" = "MIT";
        };
      };
    };
  in {
    packages = forEach allSystems (system: let
      pkgs = mkPkgs system;
    in {
      default = mkUmbra pkgs;
      umbra = mkUmbra pkgs;
      umbra-agent = mkUmbraAgent pkgs;
    } // nixpkgs.lib.optionalAttrs (builtins.elem system linuxSystems) {
      image = mkImage system;
    });

    apps = forEach allSystems (system: let
      substrateLib = mkSubstrateLib system;
    in {
      default = {
        type = "app";
        program = "${mkUmbra (mkPkgs system)}/bin/umbra";
      };
      umbra-agent = {
        type = "app";
        program = "${mkUmbraAgent (mkPkgs system)}/bin/umbra-agent";
      };
      # Multi-arch release via substrate helper
      release = substrateLib.mkImageReleaseApp {
        name = "umbra-agent";
        inherit registry mkImage;
      };
    });

    devShells = forEach allSystems (system: let
      pkgs = mkPkgs system;
    in {
      default = pkgs.mkShell {
        nativeBuildInputs = [
          pkgs.cargo
          pkgs.rustc
          pkgs.pkg-config
        ];
        buildInputs = darwinBuildInputs pkgs;
        RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
      };
    });
  };
}
