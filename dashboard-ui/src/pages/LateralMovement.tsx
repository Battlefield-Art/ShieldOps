import { useState } from "react";
import { ArrowRight, Shield, AlertTriangle, GitBranch, Target, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "paths" | "blast_radius" | "response";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "paths", label: "Movement Paths" },
  { id: "blast_radius", label: "Blast Radius" },
  { id: "response", label: "Response Actions" },
];

export default function LateralMovement() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Lateral Movement Detector" subtitle="Identity-based lateral movement detection across cloud boundaries" icon={<GitBranch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Detections" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Signals Analyzed (24h)" value="12.4K" icon={<Zap className="h-5 w-5" />} />
        <MetricCard title="Paths Identified" value="7" icon={<GitBranch className="h-5 w-5" />} />
        <MetricCard title="Auto-Contained" value="4" icon={<Shield className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Movement Type Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ type: "OAuth Token Reuse", count: 3, severity: "critical" }, { type: "Cross-Cloud Escalation", count: 2, severity: "high" }, { type: "Service Account Pivoting", count: 2, severity: "medium" }].map((m) => (
              <div key={m.type} className="card-interactive p-4">
                <div className="flex items-center justify-between mb-2"><span className="text-sm text-white/60">{m.type}</span><StatusBadge status={m.severity} /></div>
                <p className="text-2xl font-bold text-white">{m.count} paths</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "paths" && (
        <div className="space-y-3">
          {[
            { id: "PATH-001", type: "Cross-Cloud Escalation", from: "AWS svc-admin", to: "GCP project-admin", clouds: "AWS → GCP", hops: 3, confidence: 92, mitre: "T1078.004", severity: "critical" },
            { id: "PATH-002", type: "OAuth Token Reuse", from: "user@corp.com (Slack)", to: "user@corp.com (GitHub)", clouds: "Slack → GitHub", hops: 1, confidence: 88, mitre: "T1528", severity: "high" },
            { id: "PATH-003", type: "Service Account Pivot", from: "k8s-deployer", to: "rds-admin", clouds: "K8s → AWS", hops: 2, confidence: 79, mitre: "T1078.001", severity: "medium" },
          ].map((p) => (
            <div key={p.id} className="card-interactive p-5">
              <div className="flex items-start justify-between mb-3">
                <div><div className="flex items-center gap-2 mb-1"><span className="font-mono text-xs text-cyan-400">{p.id}</span><StatusBadge status={p.severity} /></div><h4 className="text-white/90 font-medium">{p.type}</h4></div>
                <span className="text-xs text-white/40">{p.confidence}% confidence</span>
              </div>
              <div className="flex items-center gap-2 text-sm text-white/60">
                <span>{p.from}</span><ArrowRight className="h-3 w-3 text-cyan-400" /><span>{p.to}</span>
                <span className="text-white/40 ml-2">| {p.hops} hops | {p.mitre}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "blast_radius" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Blast Radius Assessment</h3>
          {[
            { path: "PATH-001", resources: 14, identities: 6, data: "Production DB, Customer PII", severity: "critical" },
            { path: "PATH-002", resources: 8, identities: 3, data: "Source code, CI secrets", severity: "high" },
          ].map((b) => (
            <div key={b.path} className="card-interactive p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs text-cyan-400">{b.path}</span><StatusBadge status={b.severity} />
              </div>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div><p className="text-white/50">Resources</p><p className="text-white font-bold">{b.resources}</p></div>
                <div><p className="text-white/50">Identities</p><p className="text-white font-bold">{b.identities}</p></div>
                <div><p className="text-white/50">Data at Risk</p><p className="text-white/80 text-xs">{b.data}</p></div>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "response" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Response Actions Taken</h3>
          {[
            { action: "Token Revocation", target: "OAuth token for svc-admin (AWS→GCP)", status: "completed", auto: true },
            { action: "Session Kill", target: "Active sessions for user@corp.com (GitHub)", status: "completed", auto: true },
            { action: "Role Assumption Block", target: "GCP project-admin cross-account role", status: "pending", auto: false },
          ].map((a, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{a.action}</p><p className="text-xs text-white/50">{a.target}</p></div>
              <div className="flex items-center gap-2"><span className="text-xs text-white/40">{a.auto ? "Auto" : "Manual"}</span><StatusBadge status={a.status} /></div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
