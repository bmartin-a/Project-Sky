import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";
import type { AssetCriticality, TargetType } from "../lib/types";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorNote,
  Field,
  Input,
  Select,
  Spinner,
} from "../components/ui";

const targetTypes: TargetType[] = [
  "Hostname",
  "IpAddress",
  "CidrRange",
  "Url",
  "ContainerImage",
];
const criticalities: AssetCriticality[] = ["Low", "Medium", "High", "Critical"];

export default function TargetsPage() {
  const qc = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.listTargets });

  const [address, setAddress] = useState("");
  const [type, setType] = useState<TargetType>("Hostname");
  const [criticality, setCriticality] = useState<AssetCriticality>("Medium");
  const [name, setName] = useState("");

  const create = useMutation({
    mutationFn: () =>
      api.createTarget({ address, type, criticality, name: name || null }),
    onSuccess: () => {
      setAddress("");
      setName("");
      void qc.invalidateQueries({ queryKey: ["targets"] });
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Targets</h1>
        <p className="mt-1 text-sm text-slate-400">
          Systems you are authorized to scan. Add one, then allowlist it in a
          scan policy before scanning.
        </p>
      </div>

      <Card>
        <CardHeader title="Add target" />
        <form
          className="grid grid-cols-1 gap-4 p-5 md:grid-cols-5"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <div className="md:col-span-2">
            <Field label="Address">
              <Input
                value={address}
                required
                placeholder="scanme.nmap.org"
                onChange={(e) => setAddress(e.target.value)}
              />
            </Field>
          </div>
          <Field label="Type">
            <Select
              value={type}
              onChange={(e) => setType(e.target.value as TargetType)}
            >
              {targetTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Criticality">
            <Select
              value={criticality}
              onChange={(e) =>
                setCriticality(e.target.value as AssetCriticality)
              }
            >
              {criticalities.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </Field>
          <div className="flex items-end">
            <Button type="submit" disabled={create.isPending} className="w-full">
              {create.isPending ? <Spinner /> : "Add target"}
            </Button>
          </div>
          <div className="md:col-span-2">
            <Field label="Name (optional)">
              <Input
                value={name}
                placeholder="Public web host"
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
          </div>
          {create.isError && (
            <div className="md:col-span-5">
              <ErrorNote error={create.error} />
            </div>
          )}
        </form>
      </Card>

      <Card>
        <CardHeader title="All targets" />
        {targets.isLoading ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : targets.isError ? (
          <div className="p-5">
            <ErrorNote error={targets.error} />
          </div>
        ) : targets.data && targets.data.length > 0 ? (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr className="border-b border-slate-800">
                <th className="px-5 py-3 font-medium">Address</th>
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="px-5 py-3 font-medium">Criticality</th>
                <th className="px-5 py-3 font-medium">Name</th>
                <th className="px-5 py-3 font-medium">Added</th>
              </tr>
            </thead>
            <tbody>
              {targets.data.map((t) => (
                <tr
                  key={t.id}
                  className="border-b border-slate-800/60 last:border-0"
                >
                  <td className="px-5 py-3 font-mono text-slate-200">
                    {t.address}
                  </td>
                  <td className="px-5 py-3 text-slate-400">{t.type}</td>
                  <td className="px-5 py-3 text-slate-400">{t.criticality}</td>
                  <td className="px-5 py-3 text-slate-400">{t.name ?? "—"}</td>
                  <td className="px-5 py-3 text-slate-500">
                    {formatDate(t.createdAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState message="No targets yet. Add your first target above." />
        )}
      </Card>
    </div>
  );
}
