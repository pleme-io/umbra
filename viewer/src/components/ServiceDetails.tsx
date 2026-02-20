import { useState } from "react";
import type { ServiceTypeResult } from "../types";

export function ServiceDetails({
  services,
}: {
  services: ServiceTypeResult[];
}) {
  const [expanded, setExpanded] = useState<string | null>(null);

  const sorted = [...services].sort((a, b) => {
    if (a.reachable !== b.reachable) return a.reachable ? -1 : 1;
    return b.confidence - a.confidence;
  });

  return (
    <div className="bg-umbra-card border border-umbra-border rounded-xl p-6">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-umbra-muted mb-4">
        Service Details
      </h2>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-umbra-border text-umbra-muted text-xs uppercase tracking-wider">
              <th className="text-left py-2 pr-4">Service</th>
              <th className="text-left py-2 pr-4">Endpoint</th>
              <th className="text-left py-2 pr-4">Type</th>
              <th className="text-center py-2 pr-4">Confidence</th>
              <th className="text-center py-2 pr-4">TLS</th>
              <th className="text-right py-2">Latency</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((svc) => {
              const key = `${svc.host}:${svc.port}`;
              const isExpanded = expanded === key;
              return (
                <ServiceRow
                  key={key}
                  service={svc}
                  expanded={isExpanded}
                  onToggle={() => setExpanded(isExpanded ? null : key)}
                />
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ServiceRow({
  service: svc,
  expanded,
  onToggle,
}: {
  service: ServiceTypeResult;
  expanded: boolean;
  onToggle: () => void;
}) {
  const typeLabel = svc.serviceTypeLabel;

  return (
    <>
      <tr
        onClick={onToggle}
        className={`border-b border-umbra-border/50 cursor-pointer transition-colors hover:bg-umbra-surface/30 ${
          !svc.reachable ? "opacity-50" : ""
        }`}
      >
        <td className="py-2.5 pr-4">
          <div className="flex items-center gap-2">
            <div
              className={`w-1.5 h-1.5 rounded-full ${
                svc.reachable ? "bg-umbra-success" : "bg-umbra-error"
              }`}
            />
            <span className="font-medium text-umbra-text">
              {svc.name || "—"}
            </span>
          </div>
        </td>
        <td className="py-2.5 pr-4 mono text-umbra-muted text-xs">
          {svc.host}:{svc.port}
        </td>
        <td className="py-2.5 pr-4">
          <span className="text-xs">{typeLabel}</span>
        </td>
        <td className="py-2.5 pr-4 text-center">
          <ConfidenceBar value={svc.confidence} />
        </td>
        <td className="py-2.5 pr-4 text-center">
          {svc.tls ? (
            <span className="text-umbra-success text-xs">Yes</span>
          ) : (
            <span className="text-umbra-muted text-xs">No</span>
          )}
        </td>
        <td className="py-2.5 text-right mono text-xs text-umbra-muted">
          {svc.latencyMs != null ? `${svc.latencyMs}ms` : "—"}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} className="py-3 px-4 bg-umbra-bg/50">
            <div className="space-y-2">
              {svc.evidence.length > 0 && (
                <div>
                  <div className="text-xs text-umbra-muted uppercase tracking-wider mb-1">
                    Evidence
                  </div>
                  {svc.evidence.map((e, i) => (
                    <div
                      key={i}
                      className="text-xs mono text-umbra-text/70 py-0.5"
                    >
                      {e}
                    </div>
                  ))}
                </div>
              )}
              {svc.serverHeader && (
                <div className="text-xs">
                  <span className="text-umbra-muted">Server: </span>
                  <span className="mono text-umbra-text/70">
                    {svc.serverHeader}
                  </span>
                </div>
              )}
              {svc.httpStatus != null && (
                <div className="text-xs">
                  <span className="text-umbra-muted">HTTP Status: </span>
                  <span className="mono text-umbra-text/70">
                    {svc.httpStatus}
                  </span>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 90
      ? "bg-umbra-success"
      : pct >= 70
        ? "bg-umbra-accent"
        : pct >= 50
          ? "bg-umbra-warning"
          : "bg-umbra-muted";

  return (
    <div className="flex items-center gap-2">
      <div className="w-12 h-1.5 bg-umbra-border rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs mono text-umbra-muted">{pct}%</span>
    </div>
  );
}
