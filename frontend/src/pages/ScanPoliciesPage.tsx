import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorNote,
  Field,
  Input,
  Pill,
  Spinner,
} from "../components/ui";

export default function ScanPoliciesPage() {
  const qc = useQueryClient();
  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: api.listScanPolicies,
  });

  const [name, setName] = useState("");
  const [allowed, setAllowed] = useState("");
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [allowLoopback, setAllowLoopback] = useState(false);
  const [allowMeta, setAllowMeta] = useState(false);

  const create = useMutation({
    mutationFn: () =>
      api.createScanPolicy({
        name,
        allowedTargets: allowed
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
        allowPrivateRanges: allowPrivate,
        allowLoopback,
        allowLinkLocalAndMetadata: allowMeta,
      }),
    onSuccess: () => {
      setName("");
      setAllowed("");
      setAllowPrivate(false);
      setAllowLoopback(false);
      setAllowMeta(false);
      void qc.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Scan policies</h1>
        <p className="mt-1 text-sm text-slate-400">
          Scope control. A target can only be scanned if it matches a policy's
          allowlist. Private, loopback, and cloud-metadata addresses are blocked
          unless explicitly enabled.
        </p>
      </div>

      <Card>
        <CardHeader title="New policy" />
        <form
          className="space-y-4 p-5"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Field label="Name">
              <Input
                value={name}
                required
                placeholder="Lab network"
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label="Allowed targets (comma or newline separated)">
              <Input
                value={allowed}
                required
                placeholder="scanme.nmap.org, 198.51.100.0/24"
                onChange={(e) => setAllowed(e.target.value)}
              />
            </Field>
          </div>

          <div className="flex flex-wrap gap-5">
            <Toggle
              label="Allow private ranges (RFC1918)"
              checked={allowPrivate}
              onChange={setAllowPrivate}
            />
            <Toggle
              label="Allow loopback"
              checked={allowLoopback}
              onChange={setAllowLoopback}
            />
            <Toggle
              label="Allow link-local / metadata"
              checked={allowMeta}
              onChange={setAllowMeta}
            />
          </div>

          <div className="flex items-center gap-3">
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? <Spinner /> : "Create policy"}
            </Button>
            {create.isError && <ErrorNote error={create.error} />}
          </div>
        </form>
      </Card>

      <Card>
        <CardHeader title="Policies" />
        {policies.isLoading ? (
          <div className="p-5">
            <Spinner />
          </div>
        ) : policies.data && policies.data.length > 0 ? (
          <div className="divide-y divide-slate-800/60">
            {policies.data.map((p) => (
              <div key={p.id} className="px-5 py-4">
                <div className="flex items-center justify-between">
                  <div className="font-medium text-slate-100">{p.name}</div>
                  <div className="flex gap-1.5">
                    {p.allowPrivateRanges && (
                      <Pill className="bg-amber-500/15 text-amber-300 ring-amber-500/30">
                        private
                      </Pill>
                    )}
                    {p.allowLoopback && (
                      <Pill className="bg-amber-500/15 text-amber-300 ring-amber-500/30">
                        loopback
                      </Pill>
                    )}
                    {p.allowLinkLocalAndMetadata && (
                      <Pill className="bg-red-500/15 text-red-300 ring-red-500/30">
                        metadata
                      </Pill>
                    )}
                  </div>
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {p.allowedTargets.map((t) => (
                    <span
                      key={t}
                      className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No policies yet. Create one to enable scanning." />
        )}
      </Card>
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-300">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="h-4 w-4 rounded border-slate-600 bg-slate-800 accent-sky-500"
      />
      {label}
    </label>
  );
}
