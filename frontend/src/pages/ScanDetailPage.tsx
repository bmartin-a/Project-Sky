import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { subscribeToScan } from "../lib/signalr";
import { formatDate, riskBandClasses, statusClasses } from "../lib/format";
import type { ScanProgress, ScanStatus, Severity } from "../lib/types";
import { severityColor } from "../lib/format";
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorNote,
  Pill,
  Spinner,
} from "../components/ui";

const terminal: ScanStatus[] = ["Completed", "Failed", "Cancelled", "Rejected"];

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const qc = useQueryClient();
  const [progress, setProgress] = useState<ScanProgress | null>(null);

  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (q) =>
      q.state.data && !terminal.includes(q.state.data.status) ? 2500 : false,
  });

  const findings = useQuery({
    queryKey: ["findings", scanId],
    queryFn: () => api.findingsByScan(scanId!),
    enabled: !!scanId,
  });

  const targets = useQuery({ queryKey: ["targets"], queryFn: api.listTargets });
  const targetAddress = targets.data?.find(
    (t) => t.id === scan.data?.targetId,
  )?.address;

  // Live progress via SignalR; refresh persisted data when the scan ends.
  useEffect(() => {
    if (!scanId) return;
    const dispose = subscribeToScan(scanId, (p) => {
      setProgress(p);
      if (terminal.includes(p.status)) {
        void qc.invalidateQueries({ queryKey: ["scan", scanId] });
        void qc.invalidateQueries({ queryKey: ["findings", scanId] });
      }
    });
    return dispose;
  }, [scanId, qc]);

  const status = scan.data?.status;
  const running = status && !terminal.includes(status);
  const pct = progress?.percentComplete ?? (running ? 5 : 100);

  return (
    <div className="space-y-6">
      <div>
        <Link to="/scans" className="text-sm text-sky-400 hover:underline">
          ← Scans
        </Link>
        <div className="mt-2 flex items-center gap-3">
          <h1 className="text-xl font-semibold text-slate-100">
            {scan.data?.type ?? "Scan"} scan
          </h1>
          {status && <Pill className={statusClasses(status)}>{status}</Pill>}
        </div>
        {targetAddress && (
          <p className="mt-1 font-mono text-sm text-slate-400">
            {targetAddress}
          </p>
        )}
      </div>

      {scan.isError && <ErrorNote error={scan.error} />}

      {running && (
        <Card className="p-5">
          <div className="mb-2 flex items-center justify-between text-sm">
            <span className="text-slate-300">
              {progress?.message ?? "Running…"}
            </span>
            <span className="text-slate-400">{pct}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-sky-500 transition-all duration-500"
              style={{ width: `${pct}%` }}
            />
          </div>
        </Card>
      )}

      {status === "Rejected" && scan.data?.errorMessage && (
        <ErrorNote error={`Rejected: ${scan.data.errorMessage}`} />
      )}
      {status === "Failed" && scan.data?.errorMessage && (
        <ErrorNote error={`Failed: ${scan.data.errorMessage}`} />
      )}

      <Card>
        <CardHeader
          title="Findings"
          subtitle={
            scan.data
              ? `Created ${formatDate(scan.data.createdAt)} · Completed ${formatDate(
                  scan.data.completedAt,
                )}`
              : undefined
          }
        />
        {findings.isLoading ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : findings.data && findings.data.length > 0 ? (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr className="border-b border-slate-800">
                <th className="px-5 py-3 font-medium">Severity</th>
                <th className="px-5 py-3 font-medium">Finding</th>
                <th className="px-5 py-3 font-medium">Port/Service</th>
                <th className="px-5 py-3 font-medium">CVE</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">State</th>
              </tr>
            </thead>
            <tbody>
              {findings.data.map((f) => (
                <tr
                  key={f.id}
                  className="border-b border-slate-800/60 last:border-0 align-top"
                >
                  <td className="px-5 py-3">
                    <SeverityDot severity={f.severity} />
                  </td>
                  <td className="px-5 py-3">
                    <div className="font-medium text-slate-100">{f.title}</div>
                    {f.description && (
                      <div className="mt-0.5 text-xs text-slate-500">
                        {f.description}
                      </div>
                    )}
                  </td>
                  <td className="px-5 py-3 text-slate-400">
                    {f.port
                      ? `${f.protocol}/${f.port}${f.service ? ` · ${f.service}` : ""}`
                      : "—"}
                  </td>
                  <td className="px-5 py-3">
                    {f.cveId ? (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${f.cveId}`}
                        target="_blank"
                        rel="noreferrer"
                        className="font-mono text-sky-400 hover:underline"
                      >
                        {f.cveId}
                      </a>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    <Pill className={riskBandClasses(f.riskBand)}>
                      {f.riskScore} · {f.riskBand}
                    </Pill>
                  </td>
                  <td className="px-5 py-3 text-slate-400">{f.state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState
            message={
              running
                ? "Scan in progress — findings will appear when it completes."
                : "No findings recorded for this scan."
            }
          />
        )}
      </Card>
    </div>
  );
}

function SeverityDot({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span
        className="h-2.5 w-2.5 rounded-full"
        style={{ backgroundColor: severityColor[severity] }}
      />
      <span className="text-slate-300">{severity}</span>
    </span>
  );
}
