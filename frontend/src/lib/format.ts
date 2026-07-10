import type { ScanStatus, Severity } from "./types";

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// Semantic severity colors (accessible on a dark background).
export const severityColor: Record<Severity, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#d97706",
  Low: "#2563eb",
  Info: "#6b7280",
};

export const severityOrder: Severity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
];

export function statusClasses(status: ScanStatus): string {
  switch (status) {
    case "Completed":
      return "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30";
    case "Running":
      return "bg-blue-500/15 text-blue-300 ring-blue-500/30";
    case "Queued":
      return "bg-slate-500/15 text-slate-300 ring-slate-500/30";
    case "Failed":
      return "bg-red-500/15 text-red-300 ring-red-500/30";
    case "Rejected":
      return "bg-orange-500/15 text-orange-300 ring-orange-500/30";
    case "Cancelled":
      return "bg-slate-500/15 text-slate-400 ring-slate-500/30";
  }
}

export function riskBandClasses(band: string): string {
  switch (band) {
    case "Critical":
      return "bg-red-500/15 text-red-300 ring-red-500/30";
    case "High":
      return "bg-orange-500/15 text-orange-300 ring-orange-500/30";
    case "Medium":
      return "bg-amber-500/15 text-amber-300 ring-amber-500/30";
    default:
      return "bg-slate-500/15 text-slate-300 ring-slate-500/30";
  }
}
