import type { ProtocolSummary } from "../types";

const PROTOCOL_CONFIG: {
  key: keyof Omit<ProtocolSummary, "__typename">;
  label: string;
  color: string;
}[] = [
  { key: "rest", label: "REST", color: "#3b82f6" },
  { key: "graphql", label: "GraphQL", color: "#e879f9" },
  { key: "grpc", label: "gRPC", color: "#8b5cf6" },
  { key: "websocket", label: "WebSocket", color: "#06b6d4" },
  { key: "database", label: "Database", color: "#f59e0b" },
  { key: "messageQueue", label: "MQ", color: "#10b981" },
  { key: "staticFiles", label: "Static", color: "#64748b" },
  { key: "unknown", label: "Unknown", color: "#475569" },
];

export function ProtocolBreakdown({
  protocols,
}: {
  protocols: ProtocolSummary;
}) {
  const total = PROTOCOL_CONFIG.reduce(
    (sum, p) => sum + (protocols[p.key] as number),
    0,
  );
  if (total === 0) return null;

  const active = PROTOCOL_CONFIG.filter((p) => (protocols[p.key] as number) > 0);

  return (
    <div className="bg-umbra-card border border-umbra-border rounded-xl p-6">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-umbra-muted mb-4">
        Protocol Distribution
      </h2>

      {/* Bar chart */}
      <div className="flex h-8 rounded-lg overflow-hidden mb-4">
        {active.map((p) => {
          const count = protocols[p.key] as number;
          const pct = (count / total) * 100;
          return (
            <div
              key={p.key}
              className="transition-all duration-500 hover:opacity-80"
              style={{
                width: `${pct}%`,
                backgroundColor: p.color,
                minWidth: count > 0 ? "2px" : 0,
              }}
              title={`${p.label}: ${count} (${Math.round(pct)}%)`}
            />
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4">
        {active.map((p) => (
          <div key={p.key} className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-sm"
              style={{ backgroundColor: p.color }}
            />
            <span className="text-sm text-umbra-text">{p.label}</span>
            <span className="text-sm mono text-umbra-muted">
              {protocols[p.key] as number}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
