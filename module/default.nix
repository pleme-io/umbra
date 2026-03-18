# umbra home-manager module — MCP server entry only
#
# Umbra runs in-cluster (no local daemon). This module only registers
# the MCP server with anvil for all AI coding agents.
#
# Namespace: services.umbra.mcp.*
#
# Module factory: receives { hmHelpers } from flake.nix, returns HM module.
{ hmHelpers }:
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  inherit (hmHelpers) mkMcpOptions mkAnvilRegistration;
  mcpCfg = config.services.umbra.mcp;
in {
  options.services.umbra.mcp = mkMcpOptions {
    defaultPackage = pkgs.umbra;
  };

  config = mkIf mcpCfg.enable (mkAnvilRegistration {
    name = "umbra";
    command = "umbra";
    package = mcpCfg.package;
    description = "Kubernetes container diagnostics";
    scopes = mcpCfg.scopes;
  });
}
