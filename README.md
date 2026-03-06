# umbra

Kubernetes container diagnostic MCP proxy.

## Overview

Umbra is a local MCP (Model Context Protocol) proxy that enables AI assistants to diagnose issues inside Kubernetes containers. It runs locally as an MCP server, forwarding diagnostic requests to an in-container agent (`umbra-agent`) via kubectl exec. The agent collects container-side data (DNS resolution, network connectivity, process info, filesystem state) and returns structured results.

## Architecture

```
Claude Code  -->  umbra (local MCP proxy)  -->  kubectl exec  -->  umbra-agent (in container)
```

## Crates

| Crate | Description |
|-------|-------------|
| `umbra` | Local MCP proxy server -- routes tool calls to containers |
| `umbra-agent` | Container-side MCP agent -- executes diagnostic commands |
| `umbra-core` | Shared types and K8s environment parsing |

## Usage

```bash
# Build all crates
nix build
# or
cargo build --release

# Run the local MCP proxy
umbra

# The agent binary is deployed into target containers
umbra-agent
```

## MCP Tools

The proxy exposes diagnostic tools via MCP that AI assistants can invoke to inspect container state: DNS lookups, HTTP probes, process listings, file reads, environment inspection, and network connectivity checks.

## License

MIT
