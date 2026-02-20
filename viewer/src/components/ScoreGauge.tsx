export function ScoreGauge({ score }: { score: number }) {
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const color =
    score >= 80
      ? "text-umbra-success"
      : score >= 60
        ? "text-umbra-warning"
        : "text-umbra-error";

  const strokeColor =
    score >= 80 ? "#10b981" : score >= 60 ? "#f59e0b" : "#ef4444";

  const label =
    score >= 90
      ? "Excellent"
      : score >= 80
        ? "Good"
        : score >= 60
          ? "Fair"
          : score >= 40
            ? "Poor"
            : "Critical";

  return (
    <div className="bg-umbra-card border border-umbra-border rounded-xl p-6 flex flex-col items-center">
      <div className="text-xs text-umbra-muted uppercase tracking-wider mb-3">
        Security Score
      </div>
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke="#2a2a30"
            strokeWidth="8"
          />
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke={strokeColor}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold mono ${color}`}>{score}</span>
          <span className="text-xs text-umbra-muted">/100</span>
        </div>
      </div>
      <div className={`text-sm font-medium mt-2 ${color}`}>{label}</div>
    </div>
  );
}
