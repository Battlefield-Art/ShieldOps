import { useState } from "react";
import { Fingerprint, Shield, AlertTriangle, Eye, UserX, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "anomalies" | "identity_risk" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "anomalies", label: "Anomalies" },
  { id: "identity_risk", label: "Identity Risk" },
  { id: "metrics", label: "Metrics" },
];

const ANOMALIES = [
  { id: "ITD-001", user: "admin@corp.io", threat: "Impossible Travel", locations: "New York → Shanghai (2h)", risk: "critical", detail: "Admin login from Shanghai 2 hours after New York session" },
  { id: "ITD-002", user: "svc-deploy-01", threat: "Credential Stuffing", locations: "Multiple IPs", risk: "critical", detail: "480 failed login attempts from 12 different IPs in 5 minutes" },
  { id: "ITD-003", user: "jdoe@corp.io", threat: "MFA Bypass", locations: "Unknown device", risk: "high", detail: "Successful login without MFA from unregistered device" },
  { id: "ITD-004", user: "mchen@corp.io", threat: "Privilege Escalation", locations: "Internal", risk: "high", detail: "Self-assigned Global Admin role outside change window" },
  { id: "ITD-005", user: "contractor-42", threat: "Account Takeover", locations: "TOR exit node", risk: "critical", detail: "Login from TOR network with password change attempt" },
];

export default function IdentityThreatDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Identity Threat Detector" subtitle="Identity-based threat detection and response (ITDR)" icon={<Fingerprint className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Auth Events" value="48,291" icon={<Eye className="h-5 w-5" />} />
        <MetricCard title="Anomalies" value="37" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Accounts Locked" value="8" icon={<UserX className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Max Risk Score" value="94" icon={<Shield className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Type Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Impossible Travel", v: "12", c: "text-red-400" }, { l: "Credential Stuffing", v: "8", c: "text-orange-400" }, { l: "MFA Bypass", v: "6", c: "text-yellow-400" }, { l: "Account Takeover", v: "11", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.threat}</span><span className="ml-2 text-xs text-white/40">{a.user}</span></div><StatusBadge status={a.risk} /></div><p className="text-white/50 text-sm">{a.detail}</p><span className="text-xs text-white/40">Locations: {a.locations}</span></div>))}</div>)}
      {tab === "identity_risk" && (<div className="card-surface p-6"><h3 className="section-heading">High-Risk Identities</h3><div className="space-y-2">{[{ user: "admin@corp.io", role: "Global Admin", risk: 94, threats: 3, status: "critical" }, { user: "svc-deploy-01", role: "Service Account", risk: 88, threats: 2, status: "critical" }, { user: "contractor-42", role: "Contractor", risk: 82, threats: 1, status: "high" }, { user: "mchen@corp.io", role: "Engineering", risk: 71, threats: 1, status: "high" }, { user: "jdoe@corp.io", role: "Marketing", risk: 65, threats: 1, status: "medium" }].map((u, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70 font-mono">{u.user}</span><span className="ml-2 text-xs text-white/40">{u.role}</span></div><div className="flex gap-3"><span className="text-white/40">{u.threats} threats</span><span className="text-cyan-400 font-mono">{u.risk}</span><StatusBadge status={u.status} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">ITDR Metrics</h3>{[{ m: "Detection Accuracy", v: "96.8%", t: "+1.2% vs last month" }, { m: "Mean Time to Detect", v: "4.2s", t: "-1.8s" }, { m: "Response Automation Rate", v: "78%", t: "+12%" }, { m: "False Positive Rate", v: "2.1%", t: "-0.4%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
