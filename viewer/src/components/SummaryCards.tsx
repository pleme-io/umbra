import type { AssessmentSummary } from "../types";

interface Props {
  summary: AssessmentSummary;
  duration: number;
}

export function SummaryCards({ summary, duration }: Props) {
  const cards = [
    {
      label: "Services",
      value: summary.totalServices,
      sub: `${summary.reachableServices} reachable`,
      color: "text-umbra-accent",
    },
    {
      label: "TLS Coverage",
      value: `${Math.round(summary.tlsCoveragePercent)}%`,
      sub:
        summary.tlsCoveragePercent >= 80
          ? "good coverage"
          : "needs improvement",
      color:
        summary.tlsCoveragePercent >= 80
          ? "text-umbra-success"
          : "text-umbra-warning",
    },
    {
      label: "Protocols",
      value: Object.keys(summary.serviceTypeBreakdown).length,
      sub: "distinct types",
      color: "text-umbra-info",
    },
    {
      label: "Scan Time",
      value:
        duration >= 1000
          ? `${(duration / 1000).toFixed(1)}s`
          : `${duration}ms`,
      sub: "assessment duration",
      color: "text-umbra-muted",
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className="bg-umbra-card border border-umbra-border rounded-xl p-4"
        >
          <div className="text-xs text-umbra-muted uppercase tracking-wider">
            {card.label}
          </div>
          <div className={`text-2xl font-bold mono mt-1 ${card.color}`}>
            {card.value}
          </div>
          <div className="text-xs text-umbra-muted mt-1">{card.sub}</div>
        </div>
      ))}
    </div>
  );
}
