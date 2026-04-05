/**
 * Situations hook — fetches from API with fallback to demo data.
 *
 * When the backend is running, shows real situations.
 * When offline, shows demo data so the dashboard is always usable.
 */

import { useState, useEffect, useCallback } from "react";
import { useAPI } from "./useAPI";

export interface Situation {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  status: string;
  vendors: string[];
  mitreTechniques: string[];
  affectedAssets: number;
  correlatedEvents: number;
  timeOpen: string;
  primaryAction: string;
  agent_type?: string;
  created_at?: number;
}

interface SituationsResponse {
  situations: Situation[];
  total: number;
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
    title: "Credential Theft + Lateral Movement — Finance Domain Controller",
    description: "CrowdStrike detected Mimikatz execution on FINDC01. Defender flagged anomalous Kerberos ticket requests.",
    severity: "critical",
    status: "investigating",
    vendors: ["CrowdStrike", "Defender", "Wiz"],
    mitreTechniques: ["T1003.001", "T1021.002", "T1078"],
    affectedAssets: 14,
    correlatedEvents: 47,
    timeOpen: "12m",
    primaryAction: "Isolate FINDC01",
  },
  {
    id: "sit-b2c3d4e5f6a7",
    title: "Ransomware Pre-cursor Activity — Engineering Workstations",
    description: "PowerShell obfuscation patterns detected by CrowdStrike. Disabled security tools on 3 endpoints.",
    severity: "critical",
    status: "containing",
    vendors: ["CrowdStrike", "Defender"],
    mitreTechniques: ["T1059.001", "T1562.001"],
    affectedAssets: 8,
    correlatedEvents: 31,
    timeOpen: "28m",
    primaryAction: "Network quarantine",
  },
  {
    id: "sit-c3d4e5f6a7b8",
    title: "Cloud IAM Privilege Escalation — Production AWS Account",
    description: "Wiz detected new admin policy attachment to a service role.",
    severity: "high",
    status: "new",
    vendors: ["Wiz", "CrowdStrike"],
    mitreTechniques: ["T1078.004", "T1098"],
    affectedAssets: 3,
    correlatedEvents: 12,
    timeOpen: "5m",
    primaryAction: "Revoke IAM policy",
  },
];

export function useSituations(filters?: {
  status?: string;
  severity?: string;
  limit?: number;
}) {
  const { data, loading, error, refetch } = useAPI<SituationsResponse>(
    "/situations",
    {
      pollInterval: 30000, // Refresh every 30s
      params: {
        status: filters?.status,
        severity: filters?.severity,
        limit: filters?.limit || 50,
      },
    }
  );

  // If API fails, return demo data
  const situations = data?.situations || (error ? DEMO_SITUATIONS : []);
  const total = data?.total || situations.length;
  const isDemo = !data && !!error;

  return { situations, total, loading, error, refetch, isDemo };
}

export function useSituationStats() {
  const { data, loading, error } = useAPI<SituationStats>("/situations/stats", {
    pollInterval: 60000, // Refresh every 60s
  });

  const defaultStats: SituationStats = {
    total: 0,
    by_status: {},
    by_severity: {},
    by_agent: {},
  };

  return { stats: data || defaultStats, loading, error };
}

export default useSituations;
