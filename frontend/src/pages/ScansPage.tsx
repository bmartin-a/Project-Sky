import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { formatDate, statusClasses } from "../lib/format";
import type { ScanType } from "../lib/types";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorNote,
  Field,
  Input,
  Pill,
  Select,
  Spinner,
} from "../components/ui";

const scanTypes: { value: ScanType; label: string; enabled: boolean }[] = [
  { value: "Network", label: "Network (nmap)", enabled: true },
  { value: "Web", label: "Web app (Nuclei + OWASP ZAP)", enabled: true },
  { value: "Infrastructure", label: "Infrastructure (TLS/cert checks)", enabled: true },
];

export default function ScansPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.listScans });
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.listTargets });

  const [targetId, setTargetId] = useState("");
  const [type, setType] = useState<ScanType>("Network");

  const targetsById = useMemo(
    () => new Map((targets.data ?? []).map((t) => [t.id, t])),
    [targets.data],
  );

  const create = useMutation({
    mutationFn: () => api.createScan({ targetId, type }),
    onSuccess: (scan) => {
      void qc.invalidateQueries({ queryKey: ["scans"] });
      navigate(`/scans/${scan.id}`);
    },
  });

  const schedules = useQuery({
    queryKey: ["schedules"],
    queryFn: api.listSchedules,
  });
  const [cron, setCron] = useState("0 2 * * *");
  const createSchedule = useMutation({
    mutationFn: () => api.createSchedule({ targetId, type, cron }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["schedules"] }),
  });
  const deleteSchedule = useMutation({
    mutationFn: (id: string) => api.deleteSchedule(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["schedules"] }),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Scans</h1>
        <p className="mt-1 text-sm text-slate-400">
          Launch a scan against an authorized target and watch it run in real
          time.
        </p>
      </div>

      <Card>
        <CardHeader title="Launch scan" />
        <form
          className="grid grid-cols-1 gap-4 p-5 md:grid-cols-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (targetId) create.mutate();
          }}
        >
          <div className="md:col-span-2">
            <Field label="Target">
              <Select
                value={targetId}
                required
                onChange={(e) => setTargetId(e.target.value)}
              >
                <option value="" disabled>
                  Select a target…
                </option>
                {(targets.data ?? []).map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.address} ({t.type})
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Field label="Scan type">
            <Select
              value={type}
              onChange={(e) => setType(e.target.value as ScanType)}
            >
              {scanTypes.map((s) => (
                <option key={s.value} value={s.value} disabled={!s.enabled}>
                  {s.label}
                </option>
              ))}
            </Select>
          </Field>
          <div className="flex items-end">
            <Button
              type="submit"
              disabled={create.isPending || !targetId}
              className="w-full"
            >
              {create.isPending ? <Spinner /> : "Start scan"}
            </Button>
          </div>
          {targets.data && targets.data.length === 0 && (
            <div className="md:col-span-4 text-sm text-slate-400">
              No targets yet —{" "}
              <Link to="/targets" className="text-sky-400 hover:underline">
                add one
              </Link>{" "}
              first.
            </div>
          )}
          {create.isError && (
            <div className="md:col-span-4">
              <ErrorNote error={create.error} />
            </div>
          )}
        </form>
      </Card>

      <Card>
        <CardHeader
          title="Schedules"
          subtitle="Recurring scans (uses the target + type selected above)."
          action={
            <Button
              variant="secondary"
              disabled={!targetId || createSchedule.isPending}
              onClick={() => targetId && createSchedule.mutate()}
            >
              Add schedule
            </Button>
          }
        />
        <div className="flex items-center gap-3 border-b border-slate-800 px-5 py-3">
          <span className="text-xs text-slate-400">Cron</span>
          <Input
            value={cron}
            onChange={(e) => setCron(e.target.value)}
            className="max-w-xs font-mono"
            placeholder="0 2 * * *"
          />
          {createSchedule.isError && <ErrorNote error={createSchedule.error} />}
        </div>
        {schedules.data && schedules.data.length > 0 ? (
          <table className="w-full text-left text-sm">
            <tbody>
              {schedules.data.map((s) => (
                <tr
                  key={s.id}
                  className="border-b border-slate-800/60 last:border-0"
                >
                  <td className="px-5 py-3 font-mono text-slate-200">
                    {targetsById.get(s.targetId)?.address ?? s.targetId.slice(0, 8)}
                  </td>
                  <td className="px-5 py-3 text-slate-400">{s.type}</td>
                  <td className="px-5 py-3 font-mono text-slate-400">{s.cron}</td>
                  <td className="px-5 py-3 text-right">
                    <button
                      className="text-slate-500 hover:text-red-400"
                      onClick={() => deleteSchedule.mutate(s.id)}
                      aria-label="Delete schedule"
                    >
                      <Trash2 size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState message="No schedules yet." />
        )}
      </Card>

      <Card>
        <CardHeader title="Recent scans" />
        {scans.isLoading ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : scans.data && scans.data.length > 0 ? (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr className="border-b border-slate-800">
                <th className="px-5 py-3 font-medium">Target</th>
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Created</th>
                <th className="px-5 py-3 font-medium">Completed</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {scans.data.map((s) => (
                <tr
                  key={s.id}
                  className="border-b border-slate-800/60 last:border-0"
                >
                  <td className="px-5 py-3 font-mono text-slate-200">
                    {targetsById.get(s.targetId)?.address ?? s.targetId.slice(0, 8)}
                  </td>
                  <td className="px-5 py-3 text-slate-400">{s.type}</td>
                  <td className="px-5 py-3">
                    <Pill className={statusClasses(s.status)}>{s.status}</Pill>
                  </td>
                  <td className="px-5 py-3 text-slate-500">
                    {formatDate(s.createdAt)}
                  </td>
                  <td className="px-5 py-3 text-slate-500">
                    {formatDate(s.completedAt)}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <Link
                      to={`/scans/${s.id}`}
                      className="text-sky-400 hover:underline"
                    >
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState message="No scans yet. Launch one above." />
        )}
      </Card>
    </div>
  );
}
