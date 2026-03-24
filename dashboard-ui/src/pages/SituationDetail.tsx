import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Shield,
  MonitorSmartphone,
  Cloud,
  Clock,
  Server,
  Zap,
  CheckCircle2,
  Brain,
  Target,
} from "lucide-react";
import clsx from "clsx";
import StatusBadge from "../components/StatusBadge";

/* ─── Demo data for a single situation ─────────────────────────────── */

const SITUATION = {
  id: "sit-a1b2c3d4e5f6",
  title: "Credential Theft + Lateral Movement — Finance Domain Controller",
  description:
    "CrowdStrike detected Mimikatz execution on FINDC01. Defender flagged anomalous Kerberos ticket requests from the same host. Wiz shows the host has overprivileged cloud IAM role attached. Cross-vendor correlation indicates a coordinated attack targeting financial systems.",
  severity: "critical" as const,
  status: "investigating",
  vendors: ["CrowdStrike", "Defender", "Wiz"],
  mitreTechniques: ["T1003.001", "T1021.002", "T1078", "T1558.003"],
  killChainPhase: "Lateral Movement",
  blastRadius: "widespread",
  affectedAssets: [
    "FINDC01 (Domain Controller)",
    "FIN-WS-017 (Workstation)",
    "FIN-WS-023 (Workstation)",
    "fin-app-prod-01 (Application Server)",
    "arn:aws:iam::123456789:role/FinanceAdmin",
  ],
  createdAt: "2026-03-24T14:23:00Z",
  timeOpen: "12m",
  aiSummary:
    "An attacker has gained access to the Finance domain controller FINDC01 and executed Mimikatz for credential harvesting (T1003.001). The harvested Kerberos tickets are being used for lateral movement (T1021.002) to additional finance workstations. The compromised host also has an overprivileged AWS IAM role (T1078) that could enable cloud-level escalation. Immediate containment of FINDC01 and credential rotation is critical. Blast radius is widespread — the attacker could pivot to cloud infrastructure via the attached IAM role.",
};

const TIMELINE_EVENTS = [
  {
    id: "evt-001",
    vendor: "CrowdStrike",
    timestamp: "14:23:12",
    severity: "critical",
    title: "Mimikatz Credential Dumping Detected",
    description:
      "Process lsass.exe accessed by suspicious binary on FINDC01. Signature matches Mimikatz 2.2.0.",
    technique: "T1003.001",
  },
  {
    id: "evt-002",
    vendor: "Defender",
    timestamp: "14:24:45",
    severity: "high",
    title: "Anomalous Kerberos TGS Request",
    description:
      "Kerberoasting pattern detected — 47 TGS requests for service accounts within 90 seconds from FINDC01.",
    technique: "T1558.003",
  },
  {
    id: "evt-003",
    vendor: "CrowdStrike",
    timestamp: "14:26:01",
    severity: "high",
    title: "Lateral Movement via SMB",
    description:
      "PsExec-style remote execution detected from FINDC01 to FIN-WS-017 and FIN-WS-023.",
    technique: "T1021.002",
  },
  {
    id: "evt-004",
    vendor: "Defender",
    timestamp: "14:27:18",
    severity: "high",
    title: "New Admin Login from Unusual Source",
    description:
      "Domain Admin account authenticated from FINDC01 to fin-app-prod-01. First time this source has been used for admin access.",
    technique: "T1078",
  },
  {
    id: "evt-005",
    vendor: "Wiz",
    timestamp: "14:28:00",
    severity: "high",
    title: "Overprivileged IAM Role on Compromised Host",
    description:
      "FINDC01 has AWS IAM role FinanceAdmin attached with AdministratorAccess policy. Role has not been right-sized in 180 days.",
    technique: "T1078.004",
  },
  {
    id: "evt-006",
    vendor: "CrowdStrike",
    timestamp: "14:30:44",
    severity: "medium",
    title: "Scheduled Task Created for Persistence",
    description:
      "New scheduled task 'WindowsUpdateCheck' created on FIN-WS-017 with encoded PowerShell payload.",
    technique: "T1053.005",
  },
  {
    id: "evt-007",
    vendor: "Defender",
    timestamp: "14:32:10",
    severity: "medium",
    title: "Security Event Log Cleared",
    description:
      "Windows Security event log cleared on FINDC01. Indicator of anti-forensics activity.",
    technique: "T1070.001",
  },
];

const RECOMMENDED_ACTIONS = [
  {
    id: "act-001",
    type: "contain",
    vendor: "CrowdStrike",
    description: "Network-isolate FINDC01 via CrowdStrike RTR",
    risk: "medium",
    confidence: 0.92,
    autoApproved: true,
  },
  {
    id: "act-002",
    type: "contain",
    vendor: "Defender",
    description: "Disable compromised Domain Admin account",
    risk: "high",
    confidence: 0.88,
    autoApproved: false,
  },
  {
    id: "act-003",
    type: "contain",
    vendor: "Wiz",
    description: "Revoke FinanceAdmin IAM role permissions",
    risk: "high",
    confidence: 0.85,
    autoApproved: false,
  },
  {
    id: "act-004",
    type: "remediate",
    vendor: "Defender",
    description: "Force password reset for all Finance OU accounts",
    risk: "medium",
    confidence: 0.78,
    autoApproved: false,
  },
  {
    id: "act-005",
    type: "investigate",
    vendor: "CrowdStrike",
    description: "Collect forensic artifacts from FINDC01, FIN-WS-017, FIN-WS-023",
    risk: "low",
    confidence: 0.95,
    autoApproved: true,
  },
];

const MITRE_DETAIL = [
  { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access" },
  { id: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares", tactic: "Lateral Movement" },
  { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
  { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Persistence" },
  { id: "T1558.003", name: "Steal or Forge Kerberos Tickets: Kerberoasting", tactic: "Credential Access" },
  { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "Persistence" },
  { id: "T1070.001", name: "Indicator Removal: Clear Windows Event Logs", tactic: "Defense Evasion" },
];

/* ─── Helpers ──────────────────────────────────────────────────────── */

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 ring-red-500/20",
  high: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
};

const VENDOR_ICON: Record<string, React.ReactNode> = {
  CrowdStrike: <Shield className="h-3.5 w-3.5 text-red-400" />,
  Defender: <MonitorSmartphone className="h-3.5 w-3.5 text-blue-400" />,
  Wiz: <Cloud className="h-3.5 w-3.5 text-cyan-400" />,
};

const VENDOR_LINE_COLOR: Record<string, string> = {
  CrowdStrike: "border-red-500/40",
  Defender: "border-blue-500/40",
  Wiz: "border-cyan-500/40",
};

const VENDOR_DOT_COLOR: Record<string, string> = {
  CrowdStrike: "bg-red-500",
  Defender: "bg-blue-500",
  Wiz: "bg-cyan-500",
};

const ACTION_TYPE_BADGE: Record<string, string> = {
  contain: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  remediate: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20",
  investigate: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  escalate: "bg-red-500/10 text-red-400 ring-red-500/20",
};

function confidenceColor(c: number) {
  if (c >= 0.85) return "text-emerald-400";
  if (c >= 0.7) return "text-amber-400";
  return "text-red-400";
}

export default function SituationDetail() {
  const { id: _id } = useParams<{ id: string }>();
  // In production this would fetch by _id. Using demo data.
  const sit = SITUATION;

  return (
    <div className="space-y-6">
      {/* Back nav */}
      <Link
        to="/app/situations"
        className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to Situations
      </Link>

      {/* Header */}
      <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-6 shadow-depth">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-lg font-bold text-gray-50">{sit.title}</h1>
              <span
                className={clsx(
                  "inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ring-1 ring-inset",
                  SEVERITY_BADGE[sit.severity]
                )}
              >
                {sit.severity}
              </span>
              <StatusBadge status={sit.status} size="md" />
            </div>
            <p className="max-w-3xl text-xs leading-relaxed text-gray-400">{sit.description}</p>
            <div className="flex items-center gap-4 text-[11px] text-gray-500">
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                Open for {sit.timeOpen}
              </span>
              <span className="flex items-center gap-1">
                <Server className="h-3 w-3" />
                {sit.affectedAssets.length} assets
              </span>
              <span className="flex items-center gap-1">
                <Zap className="h-3 w-3" />
                {TIMELINE_EVENTS.length} events
              </span>
              <span className="flex items-center gap-1">
                <Target className="h-3 w-3" />
                Blast radius: {sit.blastRadius}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {sit.vendors.map((v) => (
              <span
                key={v}
                className="inline-flex items-center gap-1 rounded-md bg-surface-1 px-2 py-1 text-[11px] text-gray-300 ring-1 ring-inset ring-white/[0.06]"
              >
                {VENDOR_ICON[v]}
                {v}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left — Timeline + AI Analysis (2/3) */}
        <div className="space-y-6 lg:col-span-2">
          {/* AI Analysis */}
          <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-5 shadow-depth">
            <div className="flex items-center gap-2 mb-3">
              <Brain className="h-4 w-4 text-brand-400" />
              <h2 className="text-sm font-semibold text-gray-50">SOC Brain Analysis</h2>
            </div>
            <p className="text-xs leading-relaxed text-gray-300">{sit.aiSummary}</p>
          </div>

          {/* Event Timeline */}
          <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-5 shadow-depth">
            <h2 className="mb-4 text-sm font-semibold text-gray-50">Event Timeline</h2>
            <div className="space-y-0">
              {TIMELINE_EVENTS.map((evt, idx) => (
                <div key={evt.id} className="flex gap-3">
                  {/* Timeline line */}
                  <div className="flex flex-col items-center">
                    <div
                      className={clsx(
                        "h-3 w-3 rounded-full border-2 shrink-0 mt-1",
                        VENDOR_DOT_COLOR[evt.vendor],
                        "border-surface-2"
                      )}
                    />
                    {idx < TIMELINE_EVENTS.length - 1 && (
                      <div
                        className={clsx(
                          "w-px flex-1 border-l-2 border-dashed",
                          VENDOR_LINE_COLOR[evt.vendor]
                        )}
                      />
                    )}
                  </div>

                  {/* Event content */}
                  <div className="pb-5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[11px] font-mono text-gray-500">{evt.timestamp}</span>
                      <span className="inline-flex items-center gap-1 text-[10px] text-gray-400">
                        {VENDOR_ICON[evt.vendor]}
                        {evt.vendor}
                      </span>
                      <span
                        className={clsx(
                          "inline-flex rounded-full px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset",
                          SEVERITY_BADGE[evt.severity]
                        )}
                      >
                        {evt.severity}
                      </span>
                      {evt.technique && (
                        <span className="inline-flex rounded-md bg-purple-500/10 px-1.5 py-0.5 text-[10px] font-medium text-purple-300 ring-1 ring-inset ring-purple-500/15">
                          {evt.technique}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-xs font-medium text-gray-200">{evt.title}</p>
                    <p className="mt-0.5 text-[11px] text-gray-500">{evt.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right column (1/3) */}
        <div className="space-y-6">
          {/* Recommended Actions */}
          <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-5 shadow-depth">
            <h2 className="mb-4 text-sm font-semibold text-gray-50">Recommended Actions</h2>
            <div className="space-y-2.5">
              {RECOMMENDED_ACTIONS.map((act) => (
                <div
                  key={act.id}
                  className="rounded-lg border border-white/[0.04] bg-surface-1 p-3 transition-colors hover:border-white/[0.08]"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span
                      className={clsx(
                        "inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1 ring-inset",
                        ACTION_TYPE_BADGE[act.type]
                      )}
                    >
                      {act.type}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className={clsx("text-[10px] font-medium", confidenceColor(act.confidence))}>
                        {Math.round(act.confidence * 100)}%
                      </span>
                      {act.autoApproved && (
                        <span className="inline-flex items-center gap-0.5 rounded-md bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-400 ring-1 ring-inset ring-emerald-500/15">
                          <CheckCircle2 className="h-2.5 w-2.5" />
                          auto
                        </span>
                      )}
                    </div>
                  </div>
                  <p className="text-[11px] text-gray-300">{act.description}</p>
                  <div className="mt-2 flex items-center justify-between">
                    <span className="inline-flex items-center gap-1 text-[10px] text-gray-500">
                      {VENDOR_ICON[act.vendor]}
                      {act.vendor}
                    </span>
                    <button className="rounded-md bg-brand-600/60 px-2.5 py-1 text-[10px] font-semibold text-white transition-colors hover:bg-brand-500/80">
                      Execute
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Affected Assets */}
          <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-5 shadow-depth">
            <h2 className="mb-3 text-sm font-semibold text-gray-50">Affected Assets</h2>
            <ul className="space-y-1.5">
              {sit.affectedAssets.map((asset) => (
                <li
                  key={asset}
                  className="flex items-center gap-2 rounded-md bg-surface-1 px-3 py-2 text-[11px] text-gray-300"
                >
                  <Server className="h-3 w-3 shrink-0 text-gray-500" />
                  <span className="truncate">{asset}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* MITRE Mapping */}
          <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-5 shadow-depth">
            <h2 className="mb-3 text-sm font-semibold text-gray-50">MITRE ATT&CK Mapping</h2>
            <div className="space-y-2">
              {MITRE_DETAIL.map((m) => (
                <div
                  key={m.id}
                  className="rounded-md bg-surface-1 px-3 py-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-purple-300">{m.id}</span>
                    <span className="text-[10px] text-gray-500">{m.tactic}</span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-gray-400">{m.name}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Full Event Table */}
      <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-white/[0.04] text-left text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            <tr>
              <th className="px-5 py-3.5">Time</th>
              <th className="px-5 py-3.5">Vendor</th>
              <th className="px-5 py-3.5">Event</th>
              <th className="px-5 py-3.5">Severity</th>
              <th className="px-5 py-3.5">Technique</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.03]">
            {TIMELINE_EVENTS.map((evt) => (
              <tr key={evt.id} className="hover:bg-white/[0.02]">
                <td className="px-5 py-3 font-mono text-xs text-gray-400">{evt.timestamp}</td>
                <td className="px-5 py-3">
                  <span className="inline-flex items-center gap-1.5 text-xs text-gray-300">
                    {VENDOR_ICON[evt.vendor]}
                    {evt.vendor}
                  </span>
                </td>
                <td className="px-5 py-3">
                  <p className="text-xs font-medium text-gray-200">{evt.title}</p>
                  <p className="mt-0.5 text-[11px] text-gray-500 max-w-md truncate">{evt.description}</p>
                </td>
                <td className="px-5 py-3">
                  <StatusBadge status={evt.severity} />
                </td>
                <td className="px-5 py-3">
                  {evt.technique && (
                    <span className="inline-flex rounded-md bg-purple-500/10 px-1.5 py-0.5 text-[10px] font-medium text-purple-300 ring-1 ring-inset ring-purple-500/15">
                      {evt.technique}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
