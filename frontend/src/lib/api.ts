import type {
  CreateScanPolicyRequest,
  CreateScanRequest,
  CreateTargetRequest,
  Finding,
  Scan,
  ScanPolicy,
  ScanSchedule,
  ScanType,
  Target,
} from "./types";

import { getAccessToken } from "./authToken";
import { config } from "./config";

// Same-origin by default; the Vite dev server and the production nginx both
// proxy /api to the backend. Override via runtime config / VITE_API_BASE.
const BASE = config.apiBase;

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getAccessToken();
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
    credentials: "include",
  });

  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      /* ignore non-JSON error bodies */
    }
    throw new ApiError(res.status, message);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  // Targets
  listTargets: () => request<Target[]>("/api/targets"),
  createTarget: (body: CreateTargetRequest) =>
    request<Target>("/api/targets", { method: "POST", body: JSON.stringify(body) }),

  // Scan policies
  listScanPolicies: () => request<ScanPolicy[]>("/api/scan-policies"),
  createScanPolicy: (body: CreateScanPolicyRequest) =>
    request<ScanPolicy>("/api/scan-policies", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Scans
  listScans: () => request<Scan[]>("/api/scans"),
  getScan: (id: string) => request<Scan>(`/api/scans/${id}`),
  createScan: (body: CreateScanRequest) =>
    request<Scan>("/api/scans", { method: "POST", body: JSON.stringify(body) }),

  // Findings
  findingsByScan: (scanId: string) =>
    request<Finding[]>(`/api/scans/${scanId}/findings`),
  openFindingsByTarget: (targetId: string) =>
    request<Finding[]>(`/api/targets/${targetId}/findings`),

  // Schedules
  listSchedules: () => request<ScanSchedule[]>("/api/schedules"),
  createSchedule: (body: { targetId: string; type: ScanType; cron: string }) =>
    request<ScanSchedule>("/api/schedules", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteSchedule: (id: string) =>
    request<void>(`/api/schedules/${id}`, { method: "DELETE" }),

  // Integrations
  getIntegrations: () =>
    request<{ defenderConfigured: boolean }>("/api/integrations"),
  syncDefender: () =>
    request<{ status: string }>("/api/integrations/defender/sync", {
      method: "POST",
    }),
};
