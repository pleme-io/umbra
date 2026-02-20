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

  outputs = { nixpkgs, flake-utils, substrate, ... }: let
    linuxSystems = ["x86_64-linux" "aarch64-linux"];
    allSystems = linuxSystems ++ ["x86_64-darwin" "aarch64-darwin"];
    forEach = systems: f: nixpkgs.lib.genAttrs systems f;

    registry = "ghcr.io/pleme-io/umbra-agent";

    archTag = {
      "x86_64-linux" = "amd64";
      "aarch64-linux" = "arm64";
    };

    mkPkgs = system: import nixpkgs {
      inherit system;
      overlays = [ substrate.overlays.${system}.rust ];
    };

    darwinDeps = pkgs: pkgs.lib.optionals pkgs.stdenv.isDarwin (
      if pkgs ? apple-sdk
      then [ pkgs.apple-sdk ]
      else pkgs.lib.optionals (pkgs ? darwin) (
        with pkgs.darwin.apple_sdk.frameworks; [
          Security
          SystemConfiguration
        ]
      )
    );

    commonBuildInputs = pkgs: pkgs.lib.optionals pkgs.stdenv.isDarwin [
      pkgs.libiconv
    ] ++ darwinDeps pkgs;

    mkUmbra = pkgs: pkgs.rustPlatform.buildRustPackage {
      pname = "umbra";
      version = "0.1.0";
      src = ./.;
      cargoLock.lockFile = ./Cargo.lock;
      cargoBuildFlags = [ "--package" "umbra" ];
      nativeBuildInputs = [ pkgs.pkg-config ];
      buildInputs = commonBuildInputs pkgs;
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
      buildInputs = commonBuildInputs pkgs;
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

    # Release: build both arches + push to GHCR
    mkReleaseScript = hostPkgs: let
      pushArch = targetSystem: let
        image = mkImage targetSystem;
        arch = archTag.${targetSystem};
      in ''
        echo "==> Pushing ${registry}:${arch}-$SHORT_SHA"
        ${hostPkgs.skopeo}/bin/skopeo copy docker-archive:${image} docker://${registry}:${arch}-$SHORT_SHA
        ${hostPkgs.skopeo}/bin/skopeo copy docker-archive:${image} docker://${registry}:${arch}-latest
      '';
    in
      hostPkgs.writeShellScript "release-umbra-agent" ''
        set -euo pipefail
        SHORT_SHA=$(${hostPkgs.git}/bin/git rev-parse --short HEAD)
        echo "==> Releasing ${registry}"
        ${pushArch "x86_64-linux"}
        ${pushArch "aarch64-linux"}
        echo "==> Done: ${registry}"
      '';
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
      pkgs = mkPkgs system;
    in {
      default = {
        type = "app";
        program = "${mkUmbra pkgs}/bin/umbra";
      };
      umbra-agent = {
        type = "app";
        program = "${mkUmbraAgent pkgs}/bin/umbra-agent";
      };
      release = {
        type = "app";
        program = toString (mkReleaseScript pkgs);
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
        buildInputs = commonBuildInputs pkgs;
        RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
      };
    });
  };
}
