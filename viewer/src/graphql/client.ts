import { ApolloClient, ApolloLink, InMemoryCache } from "@apollo/client/core";
import { GET_REPORT } from "./operations";
import { transformReport } from "./transform";

/** Create the Apollo client with local-only schema */
export function createClient(): ApolloClient {
  const cache = new InMemoryCache({
    typePolicies: {
      Query: {
        fields: {
          report: {
            read(existing: unknown) {
              return existing;
            },
          },
        },
      },
      AssessmentReport: { keyFields: false },
      NetworkMap: { keyFields: false },
      SecurityReport: { keyFields: false },
      AssessmentSummary: { keyFields: false },
      ProtocolSummary: { keyFields: false },
      PodIdentity: { keyFields: false },
      SecuritySummary: { keyFields: false },
    },
  });

  return new ApolloClient({
    cache,
    link: ApolloLink.empty(),
  });
}

/** Load report from a URL and write to Apollo cache */
export async function populateCache(
  client: ApolloClient,
  reportUrl: string,
): Promise<void> {
  const raw = await loadReportJson(reportUrl);
  const transformed = transformReport(raw);

  client.writeQuery({
    query: GET_REPORT,
    data: { report: transformed },
  });
}

async function loadReportJson(
  reportUrl: string,
): Promise<Record<string, unknown>> {
  // Try the explicit URL first
  const res = await fetch(reportUrl);
  if (res.ok) {
    return (await res.json()) as Record<string, unknown>;
  }

  // Check if embedded in window
  const win = window as unknown as Record<string, unknown>;
  if (win.__UMBRA_REPORT__) {
    return win.__UMBRA_REPORT__ as Record<string, unknown>;
  }

  throw new Error(
    `Failed to fetch report: ${reportUrl} (${res.status})`,
  );
}

/** Load report JSON from a dropped file and write to cache */
export function populateCacheFromJson(
  client: ApolloClient,
  raw: Record<string, unknown>,
): void {
  const transformed = transformReport(raw);
  client.writeQuery({
    query: GET_REPORT,
    data: { report: transformed },
  });
}
