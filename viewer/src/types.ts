/** GraphQL-shaped types (camelCase, matches Apollo cache) */

export interface PodIdentity {
  __typename: "PodIdentity";
  hostname: string;
  namespace: string | null;
  serviceAccount: string | null;
  nodeName: string | null;
  podName: string | null;
  podIp: string | null;
}

export interface NetworkNode {
  __typename: "NetworkNode";
  name: string;
  host: string;
  port: number;
  serviceType: unknown; // raw JSON value
  serviceTypeLabel: string;
  reachable: boolean;
  tls: boolean;
  latencyMs: number | null;
  httpStatus: number | null;
  serverHeader: string | null;
}

export interface NetworkMap {
  __typename: "NetworkMap";
  source: PodIdentity;
  nodes: NetworkNode[];
  totalServices: number;
  reachable: number;
  unreachable: number;
  timestamp: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface SecurityFinding {
  __typename: "SecurityFinding";
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: string[];
  remediation: string | null;
}

export interface SecuritySummary {
  __typename: "SecuritySummary";
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  score: number;
}

export interface SecurityReport {
  __typename: "SecurityReport";
  findings: SecurityFinding[];
  summary: SecuritySummary;
  identity: PodIdentity;
  timestamp: string;
}

export interface ServiceTypeResult {
  __typename: "ServiceTypeResult";
  name: string;
  host: string;
  port: number;
  serviceType: unknown;
  serviceTypeLabel: string;
  confidence: number;
  evidence: string[];
  tls: boolean;
  reachable: boolean;
  latencyMs: number | null;
  httpStatus: number | null;
  serverHeader: string | null;
}

export interface ProtocolSummary {
  __typename: "ProtocolSummary";
  rest: number;
  graphql: number;
  grpc: number;
  websocket: number;
  database: number;
  messageQueue: number;
  staticFiles: number;
  unknown: number;
}

export interface AssessmentSummary {
  __typename: "AssessmentSummary";
  totalServices: number;
  reachableServices: number;
  serviceTypeBreakdown: Record<string, number>;
  securityScore: number;
  tlsCoveragePercent: number;
  protocols: ProtocolSummary;
}

export interface AssessmentReport {
  __typename: "AssessmentReport";
  id: string;
  version: string;
  source: PodIdentity;
  networkMap: NetworkMap;
  security: SecurityReport;
  serviceTypes: ServiceTypeResult[];
  summary: AssessmentSummary;
  timestamp: string;
  durationMs: number;
}

export interface GetReportData {
  report: AssessmentReport | null;
}

/** Manifest entry — lightweight summary for the gallery view */
export interface ManifestEntry {
  id: string;
  timestamp: string;
  source: {
    namespace: string | null;
    podName: string | null;
    hostname: string;
  };
  securityScore: number;
  totalServices: number;
  reachableServices: number;
  tlsCoveragePercent: number;
  durationMs: number;
  reportPath: string;
}

export interface Manifest {
  version: string;
  updated: string;
  reports: ManifestEntry[];
}

/** Get a color class for a severity level */
export function severityColor(s: Severity): string {
  const colors: Record<Severity, string> = {
    critical: "text-umbra-critical",
    high: "text-umbra-error",
    medium: "text-umbra-warning",
    low: "text-umbra-info",
    info: "text-umbra-muted",
  };
  return colors[s];
}

/** Get a bg color class for a severity level */
export function severityBg(s: Severity): string {
  const colors: Record<Severity, string> = {
    critical: "bg-umbra-critical/20",
    high: "bg-umbra-error/20",
    medium: "bg-umbra-warning/20",
    low: "bg-umbra-info/20",
    info: "bg-umbra-surface",
  };
  return colors[s];
}
