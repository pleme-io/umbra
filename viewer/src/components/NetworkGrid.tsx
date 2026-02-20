import type { NetworkNode, PodIdentity } from "../types";

interface Props {
  nodes: NetworkNode[];
  source: PodIdentity;
}

export function NetworkGrid({ nodes, source }: Props) {
  const sorted = [...nodes].sort((a, b) => {
    if (a.reachable !== b.reachable) return a.reachable ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return (
    <div className="bg-umbra-card border border-umbra-border rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-umbra-muted">
          Network Topology
        </h2>
        <div className="text-xs text-umbra-muted mono">
          from {source.namespace ?? "?"}/{source.podName ?? source.hostname}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {sorted.map((node) => (
          <NodeCard key={`${node.host}:${node.port}`} node={node} />
        ))}
      </div>
    </div>
  );
}

function NodeCard({ node }: { node: NetworkNode }) {
  const typeBadgeColor = getTypeBadgeColor(node.serviceTypeLabel);

  return (
    <div
      className={`rounded-lg border p-3 transition-all ${
        node.reachable
          ? "border-umbra-border bg-umbra-surface hover:border-umbra-accent/40 hover:shadow-[0_0_12px_rgba(139,92,246,0.1)]"
          : "border-umbra-error/30 bg-umbra-error/5 opacity-70"
      }`}
    >
      <div className="flex items-start justify-between mb-2">
        <div className="text-sm font-medium text-umbra-text truncate flex-1">
          {node.name || `${node.host}:${node.port}`}
        </div>
        <div
          className={`ml-2 flex-shrink-0 w-2 h-2 rounded-full mt-1.5 ${
            node.reachable ? "bg-umbra-success" : "bg-umbra-error"
          }`}
        />
      </div>

      <div className="mono text-xs text-umbra-muted mb-2">
        {node.host}:{node.port}
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-xs px-2 py-0.5 rounded-full ${typeBadgeColor}`}>
          {node.serviceTypeLabel}
        </span>
        {node.tls && (
          <span className="text-xs px-2 py-0.5 rounded-full bg-umbra-success/20 text-umbra-success">
            TLS
          </span>
        )}
        {node.latencyMs != null && (
          <span className="text-xs mono text-umbra-muted">
            {node.latencyMs}ms
          </span>
        )}
      </div>

      {node.serverHeader && (
        <div className="mt-2 text-xs mono text-umbra-muted truncate">
          {node.serverHeader}
        </div>
      )}
    </div>
  );
}

function getTypeBadgeColor(label: string): string {
  const colors: Record<string, string> = {
    REST: "bg-blue-500/20 text-blue-400",
    GraphQL: "bg-fuchsia-400/20 text-fuchsia-400",
    gRPC: "bg-violet-500/20 text-violet-400",
    WebSocket: "bg-cyan-500/20 text-cyan-400",
    PostgreSQL: "bg-amber-500/20 text-amber-400",
    Redis: "bg-red-500/20 text-red-400",
    MySQL: "bg-orange-500/20 text-orange-400",
    MongoDB: "bg-green-500/20 text-green-400",
    Kafka: "bg-emerald-500/20 text-emerald-400",
    NATS: "bg-teal-500/20 text-teal-400",
    Static: "bg-slate-500/20 text-slate-400",
    Unknown: "bg-slate-600/20 text-slate-500",
  };
  return colors[label] ?? "bg-slate-600/20 text-slate-500";
}
