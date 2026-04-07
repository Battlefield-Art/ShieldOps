import { useState } from "react";
import { Crosshair, Target, Shield, AlertTriangle, Play, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type TabId = "overview" | "campaigns" | "ttps" | "assessments";

interface Campaign {
  id: string;
  name: string;
  mode: "dry_run" | "read_only" | "controlled";
  status: "completed" | "running" | "planned";
  ttpsExecuted: number;
  ttpsBlocked: number;
  detectionRate: number;
  lastRun: string;
}

// ── Mock Data ────────────────────────────────────────────────────────
const CAMPAIGNS: Campaign[] = [
  { id: "camp-001", name: "Q1 Lateral Movement Assessment", mode: "controlled", status: "completed", ttpsExecuted: 24, ttpsBlocked: 19, detectionRate: 79, lastRun: "2 days ago" },
  { id: "camp-002", name: "AI Agent Credential Abuse", mode: "dry_run", status: "completed", ttpsExecuted: 12, ttpsBlocked: 10, detectionRate: 83, lastRun: "5 days ago" },
  { id: "camp-003", name: "Cloud IAM Privilege Escalation", mode: "read_only", status: "running", ttpsExecuted: 8, ttpsBlocked: 6, detectionRate: 75, lastRun: "Running now" },
  { id: "camp-004", name: "MCP Server Supply Chain", mode: "dry_run", status: "planned", ttpsExecuted: 0, ttpsBlocked: 0, detectionRate: 0, lastRun: "Scheduled" },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "campaigns", label: "Campaigns" },
  { id: "ttps", label: "TTP Coverage" },
  { id: "assessments", label: "Defense Assessment" },
];

// ── Component ────────────────────────────────────────────────────────
export default function AttackCampaign() {
  const [tab, setTab] = useState<TabId>("overview");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Campaign"
        subtitle="Orchestrate multi-step attack simulations with MITRE ATT&CK mapping"
        icon={<Crosshair className="h-6 w-6" />}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Campaigns" value="1" icon={<Play className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="TTPs Tested" value="44" icon={<Target className="h-5 w-5" />} />
        <MetricCard title="Avg Detection Rate" value="79%" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Defense Gaps" value="8" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      </div>

      <div className="tab-bar">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Campaign Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Total Simulations</p>
              <p className="text-2xl font-bold text-white mt-1">44</p>
              <p className="text-xs text-white/40">Across 3 completed campaigns</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Blocked by Defenses</p>
              <p className="text-2xl font-bold text-emerald-400 mt-1">35</p>
              <p className="text-xs text-white/40">79.5% prevention rate</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">MITRE Coverage</p>
              <p className="text-2xl font-bold text-cyan-400 mt-1">12 / 14</p>
              <p className="text-xs text-white/40">Tactics covered</p>
            </div>
          </div>
        </div>
      )}

      {tab === "campaigns" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-white/50">
                <th className="px-4 py-3">Campaign</th>
                <th className="px-4 py-3">Mode</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">TTPs</th>
                <th className="px-4 py-3">Blocked</th>
                <th className="px-4 py-3">Detection</th>
                <th className="px-4 py-3">Last Run</th>
              </tr>
            </thead>
            <tbody>
              {CAMPAIGNS.map((c) => (
                <tr key={c.id} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-white/90 font-medium">{c.name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-white/60">{c.mode}</td>
                  <td className="px-4 py-3"><StatusBadge status={c.status} /></td>
                  <td className="px-4 py-3 text-white/80">{c.ttpsExecuted}</td>
                  <td className="px-4 py-3 text-emerald-400">{c.ttpsBlocked}</td>
                  <td className="px-4 py-3 text-white/80">{c.detectionRate > 0 ? `${c.detectionRate}%` : "—"}</td>
                  <td className="px-4 py-3 text-white/50">{c.lastRun}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "ttps" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">MITRE ATT&CK Coverage</h3>
          {[
            { tactic: "Initial Access", techniques: 5, tested: 4, detected: 3 },
            { tactic: "Execution", techniques: 8, tested: 6, detected: 5 },
            { tactic: "Persistence", techniques: 6, tested: 4, detected: 4 },
            { tactic: "Privilege Escalation", techniques: 7, tested: 5, detected: 3 },
            { tactic: "Lateral Movement", techniques: 5, tested: 5, detected: 4 },
            { tactic: "Collection", techniques: 4, tested: 3, detected: 2 },
            { tactic: "Exfiltration", techniques: 3, tested: 3, detected: 3 },
          ].map((t) => (
            <div key={t.tactic} className="card-interactive p-4 flex items-center justify-between">
              <div>
                <p className="text-white/90 font-medium">{t.tactic}</p>
                <p className="text-xs text-white/50">{t.tested}/{t.techniques} techniques tested, {t.detected} detected</p>
              </div>
              <div className="flex items-center gap-1">
                {t.detected === t.tested ? (
                  <CheckCircle className="h-4 w-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-yellow-400" />
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === "assessments" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Defense Gap Analysis</h3>
          <div className="space-y-3">
            {[
              { gap: "No detection for OAuth token reuse across clouds", severity: "high", recommendation: "Add cross-cloud OAuth correlation rule" },
              { gap: "Lateral movement via K8s service account undetected", severity: "high", recommendation: "Deploy K8s RBAC monitoring" },
              { gap: "Slow response to credential stuffing (>5min)", severity: "medium", recommendation: "Tune automated blocking threshold" },
            ].map((g, i) => (
              <div key={i} className="card-interactive p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-white/90 font-medium">{g.gap}</p>
                    <p className="text-xs text-cyan-400 mt-1">{g.recommendation}</p>
                  </div>
                  <StatusBadge status={g.severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
