import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Target,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Eye,
  Zap,
  MonitorSmartphone,
  Cloud,
  Server,
  ChevronRight,
  RefreshCw,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

/* ─── Severity helpers ─────────────────────────────────────────────── */

const SEVERITY_LINE: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-amber-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 ring-red-500/20",
  high: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
};

const VENDOR_COLORS: Record<string, string> = {
  CrowdStrike: "bg-red-500/10 text-red-300 ring-red-500/15",
  Defender: "bg-blue-500/10 text-blue-300 ring-blue-500/15",
  Wiz: "bg-cyan-500/10 text-cyan-300 ring-cyan-500/15",
  Internal: "bg-gray-500/10 text-gray-300 ring-gray-500/15",
};

const MITRE_BADGE = "bg-purple-500/10 text-purple-300 ring-purple-500/15";

/* ─── Demo situations ──────────────────────────────────────────────── */

interface Situation {
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
}

const SITUATIONS: Situation[] = [
  {
    id: "sit-a1b2c3d4e5f6",
    title: "Credential Theft + Lateral Movement — Finance Domain Controller",
    description:
      "CrowdStrike detected Mimikatz execution on FINDC01. Defender flagged anomalous Kerberos ticket requests from the same host. Wiz shows the host has overprivileged cloud IAM role attached.",
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
    description:
      "Multiple engineering workstations showing PowerShell obfuscation patterns detected by CrowdStrike. Defender reports disabled security tools on 3 endpoints.",
    severity: "critical",
    status: "containing",
    vendors: ["CrowdStrike", "Defender"],
    mitreTechniques: ["T1059.001", "T1562.001", "T1486"],
    affectedAssets: 8,
    correlatedEvents: 31,
    timeOpen: "28m",
    primaryAction: "Network quarantine",
  },
  {
    id: "sit-c3d4e5f6a7b8",
    title: "Cloud IAM Privilege Escalation — Production AWS Account",
    description:
      "Wiz detected new admin policy attachment to a service role. CrowdStrike sensor on the admin workstation shows suspicious AWS CLI usage patterns.",
    severity: "high",
    status: "new",
    vendors: ["Wiz", "CrowdStrike"],
    mitreTechniques: ["T1078.004", "T1098"],
    affectedAssets: 3,
    correlatedEvents: 12,
    timeOpen: "5m",
    primaryAction: "Revoke IAM policy",
  },
  {
    id: "sit-d4e5f6a7b8c9",
    title: "Suspicious Data Exfiltration — S3 Bucket Access Anomaly",
    description:
      "Unusual volume of S3 GetObject calls from an EC2 instance flagged by Wiz. Defender shows the associated user account authenticated from a new geo-location.",
    severity: "high",
    status: "investigating",
    vendors: ["Wiz", "Defender"],
    mitreTechniques: ["T1530", "T1078"],
    affectedAssets: 5,
    correlatedEvents: 23,
    timeOpen: "18m",
    primaryAction: "Block S3 access",
  },
  {
    id: "sit-e5f6a7b8c9d0",
    title: "C2 Beacon Detection — Marketing Endpoint",
    description:
      "CrowdStrike detected periodic HTTPS beaconing to a known C2 domain from MKTG-WS-042. No lateral movement detected yet.",
    severity: "high",
    status: "new",
    vendors: ["CrowdStrike"],
    mitreTechniques: ["T1071.001", "T1573"],
    affectedAssets: 1,
    correlatedEvents: 8,
    timeOpen: "3m",
    primaryAction: "Isolate endpoint",
  },
  {
    id: "sit-f6a7b8c9d0e1",
    title: "Misconfigured Public Cloud Storage — Customer PII Exposure Risk",
    description:
      "Wiz found publicly accessible Azure Blob storage containing customer data. Defender compliance scan confirmed PII presence.",
    severity: "high",
    status: "remediating",
    vendors: ["Wiz", "Defender"],
    mitreTechniques: ["T1530"],
    affectedAssets: 2,
    correlatedEvents: 6,
    timeOpen: "42m",
    primaryAction: "Revoke public access",
  },
  {
    id: "sit-a7b8c9d0e1f2",
    title: "Brute Force Attack — VPN Gateway",
    description:
      "Defender detected 2,400+ failed authentication attempts against the VPN gateway from multiple source IPs. Rate exceeds baseline by 15x.",
    severity: "medium",
    status: "investigating",
    vendors: ["Defender"],
    mitreTechniques: ["T1110.001"],
    affectedAssets: 1,
    correlatedEvents: 2400,
    timeOpen: "1h 15m",
    primaryAction: "Block source IPs",
  },
  {
    id: "sit-b8c9d0e1f2a3",
    title: "Stale Service Account with Admin Privileges",
    description:
      "Wiz identified a service account unused for 90 days with full admin privileges across production GCP project. Low urgency but high blast radius if compromised.",
    severity: "medium",
    status: "new",
    vendors: ["Wiz"],
    mitreTechniques: ["T1078.004"],
    affectedAssets: 1,
    correlatedEvents: 2,
    timeOpen: "2h",
    primaryAction: "Disable account",
  },
  {
    id: "sit-c9d0e1f2a3b4",
    title: "Anomalous DNS Queries — Internal Nameserver",
    description:
      "CrowdStrike flagged unusual TXT record queries from an internal host. Pattern consistent with DNS tunneling but confidence is moderate.",
    severity: "low",
    status: "investigating",
    vendors: ["CrowdStrike"],
    mitreTechniques: ["T1071.004"],
    affectedAssets: 1,
    correlatedEvents: 15,
    timeOpen: "3h 20m",
    primaryAction: "Investigate DNS logs",
  },
  {
    id: "sit-d0e1f2a3b4c5",
    title: "Deprecated TLS Versions in Production Load Balancers",
    description:
      "Wiz compliance scan found 4 load balancers still accepting TLS 1.0/1.1 connections. Compliance risk for PCI-DSS.",
    severity: "low",
    status: "new",
    vendors: ["Wiz"],
    mitreTechniques: [],
    affectedAssets: 4,
    correlatedEvents: 4,
    timeOpen: "6h",
    primaryAction: "Update TLS config",
  },
];

const SEVERITY_TABS = ["All", "Critical", "High", "Medium", "Low"] as const;
type SeverityTab = (typeof SEVERITY_TABS)[number];

const STATUS_OPTIONS = [
  "All Statuses",
  "new",
  "investigating",
  "containing",
  "remediating",
  "remediated",
  "closed",
];

export default function Situations() {
  const [severityFilter, setSeverityFilter] = useState<SeverityTab>("All");
  const [statusFilter, setStatusFilter] = useState("All Statuses");
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 1500);
  };

  const filtered = SITUATIONS.filter((s) => {
    if (severityFilter !== "All" && s.severity !== severityFilter.toLowerCase()) return false;
    if (statusFilter !== "All Statuses" && s.status !== statusFilter) return false;
    return true;
  });

  const criticalCount = SITUATIONS.filter((s) => s.severity === "critical").length;
  const highCount = SITUATIONS.filter((s) => s.severity === "high").length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Situations"
        badge={{
          label: `${SITUATIONS.length} active`,
          variant: criticalCount > 0 ? "error" : "warning",
        }}
        action={{
          label: "Sweep Now",
          onClick: handleRefresh,
          icon: <RefreshCw className={clsx("h-4 w-4", refreshing && "animate-spin")} />,
          loading: refreshing,
        }}
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Active Situations"
          value={SITUATIONS.length}
          icon={<Target className="h-5 w-5" />}
          change={-12.5}
        />
        <MetricCard
          label="Avg MTTR"
          value="34m"
          icon={<Clock className="h-5 w-5" />}
          change={-18.2}
        />
        <MetricCard
          label="Auto-Resolved %"
          value="62%"
          icon={<CheckCircle2 className="h-5 w-5" />}
          change={8.4}
        />
        <MetricCard
          label="Actions Pending"
          value={criticalCount + highCount}
          icon={<AlertTriangle className="h-5 w-5" />}
          change={-5.0}
        />
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex gap-1 rounded-lg bg-surface-1 p-1">
          {SEVERITY_TABS.map((tab) => {
            const count =
              tab === "All"
                ? SITUATIONS.length
                : SITUATIONS.filter((s) => s.severity === tab.toLowerCase()).length;
            return (
              <button
                key={tab}
                onClick={() => setSeverityFilter(tab)}
                className={clsx(
                  "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                  severityFilter === tab
                    ? "bg-surface-3 text-gray-50 shadow-sm"
                    : "text-gray-400 hover:text-gray-200"
                )}
              >
                {tab}
                <span className="ml-1.5 text-[10px] text-gray-500">{count}</span>
              </button>
            );
          })}
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-white/[0.06] bg-surface-2 px-3 py-1.5 text-xs text-gray-300 outline-none focus:border-brand-500/30"
        >
          {STATUS_OPTIONS.map((opt) => (
            <option key={opt} value={opt}>
              {opt === "All Statuses" ? opt : opt.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </div>

      {/* Situation Cards */}
      <div className="space-y-3">
        {filtered.map((sit) => (
          <div
            key={sit.id}
            className="group relative flex overflow-hidden rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth transition-all duration-200 hover:border-white/[0.1] hover:bg-surface-3"
          >
            {/* Severity indicator line */}
            <div className={clsx("w-1 shrink-0", SEVERITY_LINE[sit.severity])} />

            <div className="flex flex-1 flex-col gap-3 p-5 sm:flex-row sm:items-start sm:justify-between">
              {/* Left content */}
              <div className="min-w-0 flex-1 space-y-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <Link
                    to={`/app/situations/${sit.id}`}
                    className="text-sm font-semibold text-gray-50 hover:text-brand-400 transition-colors"
                  >
                    {sit.title}
                  </Link>
                  <span
                    className={clsx(
                      "inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ring-1 ring-inset",
                      SEVERITY_BADGE[sit.severity]
                    )}
                  >
                    {sit.severity}
                  </span>
                  <StatusBadge status={sit.status} />
                </div>

                <p className="text-xs leading-relaxed text-gray-400 line-clamp-2">
                  {sit.description}
                </p>

                {/* Tags */}
                <div className="flex flex-wrap items-center gap-1.5">
                  {sit.vendors.map((v) => (
                    <span
                      key={v}
                      className={clsx(
                        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset",
                        VENDOR_COLORS[v] || VENDOR_COLORS.Internal
                      )}
                    >
                      {v === "CrowdStrike" && <Shield className="h-2.5 w-2.5" />}
                      {v === "Defender" && <MonitorSmartphone className="h-2.5 w-2.5" />}
                      {v === "Wiz" && <Cloud className="h-2.5 w-2.5" />}
                      {v}
                    </span>
                  ))}
                  {sit.mitreTechniques.map((t) => (
                    <span
                      key={t}
                      className={clsx(
                        "inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset",
                        MITRE_BADGE
                      )}
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>

              {/* Right stats + actions */}
              <div className="flex shrink-0 flex-col items-end gap-3 sm:ml-6">
                <div className="flex items-center gap-4 text-[11px] text-gray-500">
                  <span className="flex items-center gap-1">
                    <Server className="h-3 w-3" />
                    {sit.affectedAssets} assets
                  </span>
                  <span className="flex items-center gap-1">
                    <Zap className="h-3 w-3" />
                    {sit.correlatedEvents} events
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {sit.timeOpen}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button className="flex items-center gap-1.5 rounded-lg bg-brand-600/80 px-3 py-1.5 text-[11px] font-semibold text-white shadow-sm transition-colors hover:bg-brand-500">
                    <Zap className="h-3 w-3" />
                    {sit.primaryAction}
                  </button>
                  <Link
                    to={`/app/situations/${sit.id}`}
                    className="flex items-center gap-1 rounded-lg border border-white/[0.06] bg-surface-1 px-3 py-1.5 text-[11px] font-medium text-gray-300 transition-colors hover:border-white/[0.1] hover:text-gray-50"
                  >
                    <Eye className="h-3 w-3" />
                    View
                    <ChevronRight className="h-3 w-3" />
                  </Link>
                </div>
              </div>
            </div>
          </div>
        ))}

        {filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-16">
            <CheckCircle2 className="h-10 w-10 text-emerald-500/50" />
            <p className="mt-3 text-sm font-medium text-gray-400">No situations match your filters</p>
            <p className="mt-1 text-xs text-gray-600">Adjust severity or status filters to see results</p>
          </div>
        )}
      </div>
    </div>
  );
}
