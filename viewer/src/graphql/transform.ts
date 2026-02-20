/**
 * Transform raw assessment JSON (snake_case) into Apollo cache shape (camelCase + __typename).
 */

type RawReport = Record<string, unknown>;

/** Convert a snake_case string to camelCase */
function snakeToCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

/** Resolve a ServiceType value to a human-readable label */
function resolveServiceTypeLabel(st: unknown): string {
  if (typeof st === "string") {
    const labels: Record<string, string> = {
      rest: "REST",
      graphql: "GraphQL",
      grpc: "gRPC",
      websocket: "WebSocket",
      static_files: "Static",
      unknown: "Unknown",
    };
    return labels[st] ?? st;
  }
  if (st && typeof st === "object") {
    if ("database" in st) {
      const db = (st as Record<string, string>).database ?? "";
      const labels: Record<string, string> = {
        postgre_s_q_l: "PostgreSQL",
        redis: "Redis",
        my_s_q_l: "MySQL",
        mongo_d_b: "MongoDB",
        unknown: "Database",
      };
      return labels[db] ?? "Database";
    }
    if ("message_queue" in st) {
      const mq = (st as Record<string, string>).message_queue ?? "";
      const labels: Record<string, string> = {
        kafka: "Kafka",
        nats: "NATS",
        rabbit_m_q: "RabbitMQ",
        unknown: "MQ",
      };
      return labels[mq] ?? "MQ";
    }
  }
  return "Unknown";
}

/** Transform keys and add __typename for Apollo cache */
function transformObject(
  obj: Record<string, unknown>,
  typename: string,
): Record<string, unknown> {
  const result: Record<string, unknown> = { __typename: typename };
  for (const [key, value] of Object.entries(obj)) {
    result[snakeToCamel(key)] = value;
  }
  return result;
}

function transformPodIdentity(raw: RawReport): Record<string, unknown> {
  return transformObject(raw, "PodIdentity");
}

function transformNetworkNode(raw: RawReport): Record<string, unknown> {
  const node = transformObject(raw, "NetworkNode");
  node["serviceTypeLabel"] = resolveServiceTypeLabel(raw["service_type"]);
  return node;
}

function transformSecurityFinding(raw: RawReport): Record<string, unknown> {
  return transformObject(raw, "SecurityFinding");
}

function transformSecuritySummary(raw: RawReport): Record<string, unknown> {
  return transformObject(raw, "SecuritySummary");
}

function transformSecurityReport(raw: RawReport): Record<string, unknown> {
  const report = transformObject(raw, "SecurityReport");
  report["findings"] = (raw["findings"] as RawReport[]).map(
    transformSecurityFinding,
  );
  report["summary"] = transformSecuritySummary(raw["summary"] as RawReport);
  report["identity"] = transformPodIdentity(raw["identity"] as RawReport);
  return report;
}

function transformNetworkMap(raw: RawReport): Record<string, unknown> {
  const map = transformObject(raw, "NetworkMap");
  map["source"] = transformPodIdentity(raw["source"] as RawReport);
  map["nodes"] = (raw["nodes"] as RawReport[]).map(transformNetworkNode);
  return map;
}

function transformServiceTypeResult(raw: RawReport): Record<string, unknown> {
  const result = transformObject(raw, "ServiceTypeResult");
  result["serviceTypeLabel"] = resolveServiceTypeLabel(raw["service_type"]);
  return result;
}

function transformProtocolSummary(raw: RawReport): Record<string, unknown> {
  return transformObject(raw, "ProtocolSummary");
}

function transformAssessmentSummary(raw: RawReport): Record<string, unknown> {
  const summary = transformObject(raw, "AssessmentSummary");
  summary["protocols"] = transformProtocolSummary(
    raw["protocols"] as RawReport,
  );
  return summary;
}

/** Transform the full report from snake_case JSON to Apollo cache shape */
export function transformReport(
  raw: RawReport,
): Record<string, unknown> {
  const report: Record<string, unknown> = {
    __typename: "AssessmentReport",
    id: raw["id"],
    version: raw["version"],
    timestamp: raw["timestamp"],
    durationMs: raw["duration_ms"],
    source: transformPodIdentity(raw["source"] as RawReport),
    networkMap: transformNetworkMap(raw["network_map"] as RawReport),
    security: transformSecurityReport(raw["security"] as RawReport),
    serviceTypes: (raw["service_types"] as RawReport[]).map(
      transformServiceTypeResult,
    ),
    summary: transformAssessmentSummary(raw["summary"] as RawReport),
  };
  return report;
}
