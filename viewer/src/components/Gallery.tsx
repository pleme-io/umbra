import { useEffect, useState } from "react";
import type { Manifest, ManifestEntry } from "../types";

interface Props {
  onSelect: (reportPath: string) => void;
}

export function Gallery({ onSelect }: Props) {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("manifest.json")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status}`);
        return res.json() as Promise<Manifest>;
      })
      .then(setManifest)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-umbra-accent animate-pulse text-lg mono">
          Loading reports...
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-umbra-border bg-umbra-surface/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-umbra-accent/20 flex items-center justify-center">
              <svg
                className="w-5 h-5 text-umbra-accent"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">
                Umbra Assessments
              </h1>
              <p className="text-xs text-umbra-muted">
                {manifest?.reports.length ?? 0} reports
              </p>
            </div>
          </div>
          {manifest && (
            <div className="text-xs text-umbra-muted mono">
              Last updated {new Date(manifest.updated).toLocaleString()}
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {error && !manifest && (
          <div className="text-center py-16">
            <div className="text-umbra-muted text-lg mb-2">
              No manifest found
            </div>
            <div className="text-umbra-muted text-sm">
              Run <code className="mono text-umbra-accent">umbra report</code>{" "}
              with <code className="mono text-umbra-accent">--publish</code> to
              generate and upload reports.
            </div>
          </div>
        )}

        {manifest && manifest.reports.length === 0 && (
          <div className="text-center py-16 text-umbra-muted">
            No reports yet.
          </div>
        )}

        {manifest && manifest.reports.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {[...manifest.reports]
              .sort(
                (a, b) =>
                  new Date(b.timestamp).getTime() -
                  new Date(a.timestamp).getTime(),
              )
              .map((entry) => (
                <ReportCard
                  key={entry.id}
                  entry={entry}
                  onSelect={onSelect}
                />
              ))}
          </div>
        )}
      </main>
    </div>
  );
}

function ReportCard({
  entry,
  onSelect,
}: {
  entry: ManifestEntry;
  onSelect: (path: string) => void;
}) {
  const ts = new Date(entry.timestamp);
  const ns = entry.source.namespace ?? "unknown";
  const pod = entry.source.podName ?? entry.source.hostname;
  const scoreColor =
    entry.securityScore >= 80
      ? "text-umbra-success"
      : entry.securityScore >= 60
        ? "text-umbra-warning"
        : "text-umbra-error";
  const scoreBg =
    entry.securityScore >= 80
      ? "bg-umbra-success"
      : entry.securityScore >= 60
        ? "bg-umbra-warning"
        : "bg-umbra-error";

  return (
    <button
      onClick={() => onSelect(entry.reportPath)}
      className="bg-umbra-card border border-umbra-border rounded-xl p-5 text-left transition-all hover:border-umbra-accent/40 hover:shadow-[0_0_20px_rgba(139,92,246,0.1)] group"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-umbra-text truncate">
            {ns}/{pod}
          </div>
          <div className="text-xs mono text-umbra-muted mt-0.5">
            {entry.id}
          </div>
        </div>
        <div className="ml-3 flex flex-col items-center">
          <span className={`text-xl font-bold mono ${scoreColor}`}>
            {entry.securityScore}
          </span>
          <div className="w-8 h-1 rounded-full bg-umbra-border mt-1 overflow-hidden">
            <div
              className={`h-full rounded-full ${scoreBg}`}
              style={{ width: `${entry.securityScore}%` }}
            />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3 mb-3">
        <div>
          <div className="text-xs text-umbra-muted">Services</div>
          <div className="text-sm mono text-umbra-text">
            {entry.reachableServices}/{entry.totalServices}
          </div>
        </div>
        <div>
          <div className="text-xs text-umbra-muted">TLS</div>
          <div className="text-sm mono text-umbra-text">
            {Math.round(entry.tlsCoveragePercent)}%
          </div>
        </div>
        <div>
          <div className="text-xs text-umbra-muted">Duration</div>
          <div className="text-sm mono text-umbra-text">
            {entry.durationMs >= 1000
              ? `${(entry.durationMs / 1000).toFixed(1)}s`
              : `${entry.durationMs}ms`}
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <div className="text-xs text-umbra-muted">
          {ts.toLocaleDateString()} {ts.toLocaleTimeString()}
        </div>
        <span className="text-xs text-umbra-accent opacity-0 group-hover:opacity-100 transition-opacity">
          View report →
        </span>
      </div>
    </button>
  );
}
