# umbra home-manager module — MCP server entry only
#
# Umbra runs in-cluster (no local daemon). This module only registers
# an MCP server entry for consumption by blackmatter-claude (bridge pattern).
#
# Namespace: services.umbra.mcp.*
{ hmHelpers }:
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  inherit (hmHelpers) mkMcpOptions mkMcpServerEntry;
  mcpCfg = config.services.umbra.mcp;
in {
  options.services.umbra.mcp = mkMcpOptions {
    defaultPackage = pkgs.umbra;
  };

  config = mkIf mcpCfg.enable {
    services.umbra.mcp.serverEntry = mkMcpServerEntry {
      command = "${mcpCfg.package}/bin/umbra";
    };
  };
}
