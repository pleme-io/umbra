import { useEffect, useState } from "react";
import { ApolloProvider, useQuery } from "@apollo/client/react";
import type { ApolloClient } from "@apollo/client/core";
import {
  createClient,
  populateCache,
  populateCacheFromJson,
} from "./graphql/client";
import { GET_REPORT } from "./graphql/operations";
import type { GetReportData } from "./types";
import { Gallery } from "./components/Gallery";
import { Header } from "./components/Header";
import { ScoreGauge } from "./components/ScoreGauge";
import { SummaryCards } from "./components/SummaryCards";
import { ProtocolBreakdown } from "./components/ProtocolBreakdown";
import { NetworkGrid } from "./components/NetworkGrid";
import { SecurityFindings } from "./components/SecurityFindings";
import { ServiceDetails } from "./components/ServiceDetails";

type View = { kind: "gallery" } | { kind: "report"; url: string };

function resolveView(): View {
  const params = new URLSearchParams(window.location.search);
  const report = params.get("report") ?? params.get("url");
  if (report) return { kind: "report", url: report };
  return { kind: "gallery" };
}

export function App() {
  const [view, setView] = useState<View>(resolveView);

  useEffect(() => {
    const onPop = () => setView(resolveView());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  function navigateToReport(reportPath: string) {
    const url = new URL(window.location.href);
    url.searchParams.set("report", reportPath);
    window.history.pushState({}, "", url.toString());
    setView({ kind: "report", url: reportPath });
  }

  function navigateToGallery() {
    const url = new URL(window.location.href);
    url.searchParams.delete("report");
    url.searchParams.delete("url");
    window.history.pushState({}, "", url.toString());
    setView({ kind: "gallery" });
  }

  if (view.kind === "gallery") {
    return <Gallery onSelect={navigateToReport} />;
  }

  return (
    <ReportLoader
      reportUrl={view.url}
      onBack={navigateToGallery}
    />
  );
}

function ReportLoader({
  reportUrl,
  onBack,
}: {
  reportUrl: string;
  onBack: () => void;
}) {
  const [client, setClient] = useState<ApolloClient | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setClient(null);

    const apolloClient = createClient();
    populateCache(apolloClient, reportUrl)
      .then(() => setClient(apolloClient))
      .catch((e) => {
        setClient(apolloClient);
        setError(String(e));
      })
      .finally(() => setLoading(false));
  }, [reportUrl]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-umbra-accent animate-pulse text-lg mono">
          Loading assessment...
        </div>
      </div>
    );
  }

  if (!client) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-umbra-error text-lg">Failed to initialize</div>
      </div>
    );
  }

  return (
    <ApolloProvider client={client}>
      <ReportView error={error} client={client} onBack={onBack} />
    </ApolloProvider>
  );
}

function ReportView({
  error: loadError,
  client,
  onBack,
}: {
  error: string | null;
  client: ApolloClient;
  onBack: () => void;
}) {
  const { data, error: queryError } = useQuery<GetReportData>(GET_REPORT);
  const report = data?.report;

  if (!report) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4 p-8">
        <div className="text-umbra-error text-lg">No report loaded</div>
        <div className="text-umbra-muted text-sm max-w-lg text-center">
          {loadError ?? queryError?.message ?? "No report data found"}
        </div>
        <div className="flex gap-4 mt-4">
          <button
            onClick={onBack}
            className="px-4 py-2 rounded-lg bg-umbra-surface border border-umbra-border text-sm text-umbra-text hover:border-umbra-accent/40 transition-colors"
          >
            ← Back to gallery
          </button>
          <DropZone client={client} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <Header report={report} onBack={onBack} />

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-1">
            <ScoreGauge score={report.summary.securityScore} />
          </div>
          <div className="lg:col-span-3">
            <SummaryCards
              summary={report.summary}
              duration={report.durationMs}
            />
          </div>
        </div>

        <ProtocolBreakdown protocols={report.summary.protocols} />
        <NetworkGrid nodes={report.networkMap.nodes} source={report.source} />
        <SecurityFindings security={report.security} />
        <ServiceDetails services={report.serviceTypes} />
      </main>

      <footer className="border-t border-umbra-border px-6 py-4 text-center text-umbra-muted text-xs">
        Generated by Umbra v{report.version} in {report.durationMs}ms
      </footer>
    </div>
  );
}

function DropZone({ client }: { client: ApolloClient }) {
  const [dragging, setDragging] = useState(false);

  return (
    <div
      className={`w-60 h-20 border-2 border-dashed rounded-lg flex items-center justify-center transition-colors ${
        dragging ? "border-umbra-accent bg-umbra-glow" : "border-umbra-border"
      }`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files[0];
        if (file) {
          file.text().then((text) => {
            const raw = JSON.parse(text) as Record<string, unknown>;
            populateCacheFromJson(client, raw);
          });
        }
      }}
    >
      <span className="text-umbra-muted text-sm">Drop report.json</span>
    </div>
  );
}
