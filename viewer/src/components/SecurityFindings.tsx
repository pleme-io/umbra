import { useState } from "react";
import type { SecurityReport, SecurityFinding, Severity } from "../types";
import { severityColor, severityBg } from "../types";

export function SecurityFindings({ security }: { security: SecurityReport }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "all">("all");

  const filtered =
    filter === "all"
      ? security.findings
      : security.findings.filter((f) => f.severity === filter);

  const severities: (Severity | "all")[] = [
    "all",
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ];

  const counts: Record<string, number> = {
    all: security.findings.length,
    critical: security.summary.critical,
    high: security.summary.high,
    medium: security.summary.medium,
    low: security.summary.low,
    info: security.summary.info,
  };

  return (
    <div className="bg-umbra-card border border-umbra-border rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-umbra-muted">
          Security Findings
        </h2>
        <div className="text-sm mono text-umbra-muted">
          Score: {security.summary.score}/100
        </div>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2 mb-4 flex-wrap">
        {severities.map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1 rounded-full text-xs transition-colors ${
              filter === s
                ? "bg-umbra-accent/20 text-umbra-accent"
                : "bg-umbra-surface text-umbra-muted hover:text-umbra-text"
            }`}
          >
            {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}{" "}
            <span className="mono">{counts[s]}</span>
          </button>
        ))}
      </div>

      {/* Findings list */}
      <div className="space-y-2">
        {filtered.map((finding) => (
          <FindingRow
            key={finding.id}
            finding={finding}
            expanded={expandedId === finding.id}
            onToggle={() =>
              setExpandedId(expandedId === finding.id ? null : finding.id)
            }
          />
        ))}
        {filtered.length === 0 && (
          <div className="text-umbra-muted text-sm py-4 text-center">
            No findings for this filter.
          </div>
        )}
      </div>
    </div>
  );
}

function FindingRow({
  finding,
  expanded,
  onToggle,
}: {
  finding: SecurityFinding;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      className={`rounded-lg border transition-colors ${
        expanded ? "border-umbra-accent/30" : "border-umbra-border"
      }`}
    >
      <button
        onClick={onToggle}
        className="w-full px-4 py-3 flex items-center gap-3 text-left hover:bg-umbra-surface/50 rounded-lg"
      >
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-umbra-text truncate">
            {finding.title}
          </div>
          <div className="text-xs text-umbra-muted">
            {finding.category} &middot; {finding.id}
          </div>
        </div>
        <svg
          className={`w-4 h-4 text-umbra-muted transition-transform ${
            expanded ? "rotate-180" : ""
          }`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3">
          <p className="text-sm text-umbra-text/80">{finding.description}</p>

          {finding.evidence.length > 0 && (
            <div>
              <div className="text-xs text-umbra-muted uppercase tracking-wider mb-1">
                Evidence
              </div>
              <div className="space-y-1">
                {finding.evidence.map((e, i) => (
                  <div
                    key={i}
                    className="text-xs mono bg-umbra-bg px-3 py-1.5 rounded text-umbra-text/70"
                  >
                    {e}
                  </div>
                ))}
              </div>
            </div>
          )}

          {finding.remediation && (
            <div>
              <div className="text-xs text-umbra-muted uppercase tracking-wider mb-1">
                Remediation
              </div>
              <p className="text-sm text-umbra-success/80">
                {finding.remediation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`flex-shrink-0 px-2 py-0.5 rounded text-xs font-medium uppercase ${severityColor(severity)} ${severityBg(severity)}`}
    >
      {severity}
    </span>
  );
}
