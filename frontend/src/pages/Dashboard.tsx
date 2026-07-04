import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../lib/api";
import {
  formatDate,
  severityColor,
  severityOrder,
  statusClasses,
} from "../lib/format";
import type { Finding, Severity } from "../lib/types";
import { Card, CardHeader, EmptyState, Pill, Spinner } from "../components/ui";

export default function Dashboard() {
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.listTargets });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.listScans });

  // Aggregate open findings across every target.
  const findingQueries = useQueries({
    queries: (targets.data ?? []).map((t) => ({
      queryKey: ["openFindings", t.id],
      queryFn: () => api.openFindingsByTarget(t.id),
    })),
  });

  const allFindings: Finding[] = useMemo(
    () => findingQueries.flatMap((q) => q.data ?? []),
    [findingQueries],
  );

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0,
    };
    for (const f of allFindings) counts[f.severity]++;
    return counts;
  }, [allFindings]);

  const chartData = severityOrder.map((s) => ({
    name: s,
    count: severityCounts[s],
  }));

  const runningCount =
    scans.data?.filter((s) => s.status === "Running" || s.status === "Queued")
      .length ?? 0;
  const criticalHigh = severityCounts.Critical + severityCounts.High;
  const recentScans = (scans.data ?? []).slice(0, 6);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-400">
          Overview of your attack surface and recent scan activity.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Targets" value={targets.data?.length ?? 0} />
        <Stat label="Scans" value={scans.data?.length ?? 0} />
        <Stat label="Active scans" value={runningCount} />
        <Stat
          label="Critical + High"
          value={criticalHigh}
          accent={criticalHigh > 0 ? "text-red-300" : undefined}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader
            title="Open findings by severity"
            subtitle={`${allFindings.length} open finding${allFindings.length === 1 ? "" : "s"}`}
          />
          <div className="p-5">
            {allFindings.length === 0 ? (
              <EmptyState message="No open findings yet. Run a scan to populate this." />
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={chartData}>
                  <XAxis
                    dataKey="name"
                    stroke="#64748b"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    cursor={{ fill: "#1e293b55" }}
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      border: "1px solid #1e293b",
                      borderRadius: 8,
                      color: "#e2e8f0",
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((d) => (
                      <Cell key={d.name} fill={severityColor[d.name as Severity]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Recent scans" />
          {scans.isLoading ? (
            <div className="p-5">
              <Spinner />
            </div>
          ) : recentScans.length > 0 ? (
            <div className="divide-y divide-slate-800/60">
              {recentScans.map((s) => (
                <Link
                  key={s.id}
                  to={`/scans/${s.id}`}
                  className="flex items-center justify-between px-5 py-3 hover:bg-slate-800/40"
                >
                  <div className="text-sm text-slate-300">
                    {s.type}
                    <span className="ml-2 text-xs text-slate-500">
                      {formatDate(s.createdAt)}
                    </span>
                  </div>
                  <Pill className={statusClasses(s.status)}>{s.status}</Pill>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState message="No scans yet." />
          )}
        </Card>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: string;
}) {
  return (
    <Card className="p-5">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className={`mt-2 text-3xl font-semibold ${accent ?? "text-slate-100"}`}>
        {value}
      </div>
    </Card>
  );
}
