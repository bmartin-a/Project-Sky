// Mirrors the backend DTOs/enums. Enums are serialized as strings by the API
// (JsonStringEnumConverter), so these are string unions.

export type ScanType = "Network" | "Web" | "Defender" | "Infrastructure";

export type ScanStatus =
  | "Queued"
  | "Running"
  | "Completed"
  | "Failed"
  | "Cancelled"
  | "Rejected";

export type Severity = "Info" | "Low" | "Medium" | "High" | "Critical";

export type FindingState = "New" | "Existing" | "Resolved";

export type TargetType =
  | "Hostname"
  | "IpAddress"
  | "CidrRange"
  | "Url"
  | "ContainerImage";

export type AssetCriticality = "Low" | "Medium" | "High" | "Critical";

export interface Target {
  id: string;
  address: string;
  type: TargetType;
  criticality: AssetCriticality;
  name: string | null;
  createdAt: string;
}

export interface ScanPolicy {
  id: string;
  name: string;
  allowedTargets: string[];
  allowPrivateRanges: boolean;
  allowLoopback: boolean;
  allowLinkLocalAndMetadata: boolean;
}

export interface Scan {
  id: string;
  targetId: string;
  type: ScanType;
  status: ScanStatus;
  errorMessage: string | null;
  createdAt: string;
  completedAt: string | null;
}

export interface ScanSchedule {
  id: string;
  targetId: string;
  type: ScanType;
  cron: string;
  enabled: boolean;
  createdAt: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string | null;
  severity: Severity;
  state: FindingState;
  source: string;
  port: number | null;
  protocol: string | null;
  service: string | null;
  serviceVersion: string | null;
  cpe: string | null;
  cveId: string | null;
  riskScore: number;
  riskBand: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ScanProgress {
  scanId: string;
  status: ScanStatus;
  percentComplete: number;
  message: string | null;
  findingsSoFar: number;
}

// Request payloads
export interface CreateTargetRequest {
  address: string;
  type: TargetType;
  criticality: AssetCriticality;
  name?: string | null;
}

export interface CreateScanPolicyRequest {
  name: string;
  allowedTargets: string[];
  allowPrivateRanges: boolean;
  allowLoopback: boolean;
  allowLinkLocalAndMetadata: boolean;
}

export interface ScanOptions {
  ports?: string | null;
  serviceDetection?: boolean;
  osDetection?: boolean;
  runVulnScripts?: boolean;
}

export interface CreateScanRequest {
  targetId: string;
  type: ScanType;
  options?: ScanOptions;
}
