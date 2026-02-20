import type { AssessmentReport } from "../types";

interface Props {
  report: AssessmentReport;
  onBack?: () => void;
}

export function Header({ report, onBack }: Props) {
  const ts = new Date(report.timestamp);
  const ns = report.source.namespace ?? "unknown";
  const pod = report.source.podName ?? report.source.hostname;

  return (
    <header className="border-b border-umbra-border bg-umbra-surface/50 backdrop-blur-sm sticky top-0 z-10">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          {onBack && (
            <button
              onClick={onBack}
              className="w-8 h-8 rounded-lg bg-umbra-surface border border-umbra-border flex items-center justify-center text-umbra-muted hover:text-umbra-text hover:border-umbra-accent/40 transition-colors"
            >
              <svg
                className="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M15 19l-7-7 7-7"
                />
              </svg>
            </button>
          )}
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
              Umbra Assessment
            </h1>
            <p className="text-xs text-umbra-muted mono">{report.id}</p>
          </div>
        </div>

        <div className="flex items-center gap-6 text-sm">
          <div className="text-right">
            <div className="text-umbra-muted text-xs">Source</div>
            <div className="mono text-umbra-text">
              {ns}/{pod}
            </div>
          </div>
          <div className="text-right">
            <div className="text-umbra-muted text-xs">Generated</div>
            <div className="mono text-umbra-text">
              {ts.toLocaleDateString()} {ts.toLocaleTimeString()}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
