/**
 * Situations hook -- fetches from API with fallback to demo data.
 *
 * When the backend is running, shows real situations.
 * When offline, shows demo data so the dashboard is always usable.
 */


import { useAPI } from "./useAPI";

export type SituationSeverity = "critical" | "high" | "medium" | "low" | "info";
export type SituationStatus =
  | "new"
  | "investigating"
  | "containing"
  | "remediating"
  | "remediated"
  | "resolved"
  | "closed";
export type TimeRange = "1h" | "24h" | "7d" | "30d";

export interface Situation {
  id: string;
  title: string;
  description: string;
  severity: SituationSeverity;
  status: string;
  agent_name: string;
  type: string;
  vendors: string[];
  mitre_techniques: string[];
  affected_assets: number;
  correlated_events: number;
  time_open: string;
  primary_action: string;
  created_at: string;
  updated_at: string;
  details: Record<string, unknown>;
}

export interface SituationDetailData {
  id: string;
  title: string;
  description: string;
  severity: SituationSeverity;
  status: string;
  agent_name: string;
  type: string;
  vendors: string[];
  mitre_techniques: string[];
  affected_assets: string[];
  correlated_events: number;
  time_open: string;
  primary_action: string;
  ai_summary: string;
  blast_radius: string;
  created_at: string;
  updated_at: string;
  details: Record<string, unknown>;
  timeline: TimelineEntry[];
  recommended_actions: RecommendedAction[];
}

export interface TimelineEntry {
  id: string;
  timestamp: string;
  vendor: string;
  severity: string;
  title: string;
  description: string;
  technique: string;
}

export interface RecommendedAction {
  id: string;
  type: string;
  vendor: string;
  description: string;
  risk: string;
  confidence: number;
  auto_approved: boolean;
}

interface SituationsResponse {
  situations: Situation[];
  total: number;
  limit: number;
  offset: number;
}

interface SituationFilters {
  status?: string;
  severity?: string;
  agent_name?: string;
  time_range?: TimeRange;
  limit?: number;
}

interface SituationStats {
  total: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_agent: Record<string, number>;
}

// Demo data for when API is unavailable
const DEMO_SITUATIONS: Situation[] = [
  {
    id: "sit-a1b2c3d4e5f6",
    title: "Credential Theft + Lateral Movement -- Finance Domain Controller",
    description:
      "CrowdStrike detected Mimikatz execution on FINDC01. Defender flagged anomalous Kerberos ticket requests from the same host. Wiz shows the host has overprivileged cloud IAM role attached.",
    severity: "critical",
    status: "investigating",
    agent_name: "soc_analyst",
    type: "investigation",
    vendors: ["CrowdStrike", "Defender", "Wiz"],
    mitre_techniques: ["T1003.001", "T1021.002", "T1078"],
    affected_assets: 14,
    correlated_events: 47,
    time_open: "12m",
    primary_action: "Isolate FINDC01",
    created_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-b2c3d4e5f6a7",
    title: "Ransomware Pre-cursor Activity -- Engineering Workstations",
    description:
      "Multiple engineering workstations showing PowerShell obfuscation patterns detected by CrowdStrike. Defender reports disabled security tools on 3 endpoints.",
    severity: "critical",
    status: "containing",
    agent_name: "threat_hunter",
    type: "alert",
    vendors: ["CrowdStrike", "Defender"],
    mitre_techniques: ["T1059.001", "T1562.001", "T1486"],
    affected_assets: 8,
    correlated_events: 31,
    time_open: "28m",
    primary_action: "Network quarantine",
    created_at: new Date(Date.now() - 28 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-c3d4e5f6a7b8",
    title: "Cloud IAM Privilege Escalation -- Production AWS Account",
    description:
      "Wiz detected new admin policy attachment to a service role. CrowdStrike sensor on the admin workstation shows suspicious AWS CLI usage patterns.",
    severity: "high",
    status: "new",
    agent_name: "identity_graph",
    type: "investigation",
    vendors: ["Wiz", "CrowdStrike"],
    mitre_techniques: ["T1078.004", "T1098"],
    affected_assets: 3,
    correlated_events: 12,
    time_open: "5m",
    primary_action: "Revoke IAM policy",
    created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-d4e5f6a7b8c9",
    title: "Suspicious Data Exfiltration -- S3 Bucket Access Anomaly",
    description:
      "Unusual volume of S3 GetObject calls from an EC2 instance flagged by Wiz. Defender shows the associated user account authenticated from a new geo-location.",
    severity: "high",
    status: "investigating",
    agent_name: "data_loss_prevention",
    type: "alert",
    vendors: ["Wiz", "Defender"],
    mitre_techniques: ["T1530", "T1078"],
    affected_assets: 5,
    correlated_events: 23,
    time_open: "18m",
    primary_action: "Block S3 access",
    created_at: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-e5f6a7b8c9d0",
    title: "C2 Beacon Detection -- Marketing Endpoint",
    description:
      "CrowdStrike detected periodic HTTPS beaconing to a known C2 domain from MKTG-WS-042. No lateral movement detected yet.",
    severity: "high",
    status: "new",
    agent_name: "threat_hunter",
    type: "alert",
    vendors: ["CrowdStrike"],
    mitre_techniques: ["T1071.001", "T1573"],
    affected_assets: 1,
    correlated_events: 8,
    time_open: "3m",
    primary_action: "Isolate endpoint",
    created_at: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-f6a7b8c9d0e1",
    title: "Misconfigured Public Cloud Storage -- Customer PII Exposure Risk",
    description:
      "Wiz found publicly accessible Azure Blob storage containing customer data. Defender compliance scan confirmed PII presence.",
    severity: "high",
    status: "remediating",
    agent_name: "cloud_posture",
    type: "remediation",
    vendors: ["Wiz", "Defender"],
    mitre_techniques: ["T1530"],
    affected_assets: 2,
    correlated_events: 6,
    time_open: "42m",
    primary_action: "Revoke public access",
    created_at: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-a7b8c9d0e1f2",
    title: "Brute Force Attack -- VPN Gateway",
    description:
      "Defender detected 2,400+ failed authentication attempts against the VPN gateway from multiple source IPs. Rate exceeds baseline by 15x.",
    severity: "medium",
    status: "investigating",
    agent_name: "soc_analyst",
    type: "alert",
    vendors: ["Defender"],
    mitre_techniques: ["T1110.001"],
    affected_assets: 1,
    correlated_events: 2400,
    time_open: "1h 15m",
    primary_action: "Block source IPs",
    created_at: new Date(Date.now() - 75 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-b8c9d0e1f2a3",
    title: "Stale Service Account with Admin Privileges",
    description:
      "Wiz identified a service account unused for 90 days with full admin privileges across production GCP project. Low urgency but high blast radius if compromised.",
    severity: "medium",
    status: "new",
    agent_name: "identity_graph",
    type: "investigation",
    vendors: ["Wiz"],
    mitre_techniques: ["T1078.004"],
    affected_assets: 1,
    correlated_events: 2,
    time_open: "2h",
    primary_action: "Disable account",
    created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-c9d0e1f2a3b4",
    title: "Anomalous DNS Queries -- Internal Nameserver",
    description:
      "CrowdStrike flagged unusual TXT record queries from an internal host. Pattern consistent with DNS tunneling but confidence is moderate.",
    severity: "low",
    status: "investigating",
    agent_name: "threat_hunter",
    type: "investigation",
    vendors: ["CrowdStrike"],
    mitre_techniques: ["T1071.004"],
    affected_assets: 1,
    correlated_events: 15,
    time_open: "3h 20m",
    primary_action: "Investigate DNS logs",
    created_at: new Date(Date.now() - 200 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
  {
    id: "sit-d0e1f2a3b4c5",
    title: "Deprecated TLS Versions in Production Load Balancers",
    description:
      "Wiz compliance scan found 4 load balancers still accepting TLS 1.0/1.1 connections. Compliance risk for PCI-DSS.",
    severity: "low",
    status: "new",
    agent_name: "compliance_auditor",
    type: "remediation",
    vendors: ["Wiz"],
    mitre_techniques: [],
    affected_assets: 4,
    correlated_events: 4,
    time_open: "6h",
    primary_action: "Update TLS config",
    created_at: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
    details: {},
  },
];

export function useSituations(filters?: SituationFilters) {
  const params: Record<string, string | number | undefined> = {
    status: filters?.status,
    severity: filters?.severity,
    agent_name: filters?.agent_name,
    time_range: filters?.time_range,
    limit: filters?.limit || 50,
  };

  const { data, loading, error, refetch } = useAPI<SituationsResponse>(
    "/situations",
    {
      pollInterval: 30000, // Auto-refresh every 30s
      params,
    },
  );

  // If API fails, return demo data with client-side filtering
  let situations = data?.situations || (error ? DEMO_SITUATIONS : []);
  if (error && situations === DEMO_SITUATIONS) {
    // Apply client-side filters to demo data
    if (filters?.severity) {
      situations = situations.filter((s) => s.severity === filters.severity);
    }
    if (filters?.status) {
      situations = situations.filter((s) => s.status === filters.status);
    }
    if (filters?.agent_name) {
      situations = situations.filter(
        (s) => s.agent_name === filters.agent_name,
      );
    }
  }
  const total = data?.total ?? situations.length;
  const isDemo = !data && !!error;

  return { situations, total, loading, error, refetch, isDemo };
}

export function useSituationDetail(id: string | undefined) {
  const { data, loading, error, refetch } = useAPI<SituationDetailData>(
    `/situations/${id}`,
    {
      autoFetch: !!id,
      pollInterval: 30000,
    },
  );

  return { situation: data, loading, error, refetch };
}

export function useSituationStats() {
  const { data, loading, error } = useAPI<SituationStats>(
    "/situations/stats",
    {
      pollInterval: 60000, // Refresh every 60s
    },
  );

  const defaultStats: SituationStats = {
    total: 0,
    by_status: {},
    by_severity: {},
    by_agent: {},
  };

  return { stats: data || defaultStats, loading, error };
}

export function useSituationMetrics() {
  const { data, loading, error } = useAPI<{
    active_situations: number;
    avg_mttd_ms: number;
    avg_mtta_ms: number;
    avg_mttr_ms: number;
    auto_resolved_pct: number;
    actions_pending: number;
    total_sweeps: number;
  }>("/situations/metrics", {
    pollInterval: 30000,
  });

  return { metrics: data, loading, error };
}

export default useSituations;
