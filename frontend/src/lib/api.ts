import type {
  CreateScanPolicyRequest,
  CreateScanRequest,
  CreateTargetRequest,
  Finding,
  Scan,
  ScanPolicy,
  Target,
} from "./types";

// Same-origin by default; the Vite dev server and the production nginx both
// proxy /api to the backend. Override with VITE_API_BASE if needed.
const BASE = import.meta.env.VITE_API_BASE ?? "";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
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
};
