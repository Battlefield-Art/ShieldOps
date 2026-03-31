import { useState } from "react";
import { Bot, Siren, Shield, Zap, CheckCircle, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "active_responses" | "playbook_execution" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "active_responses", label: "Active Responses" },
  { id: "playbook_execution", label: "Playbook Execution" },
  { id: "metrics", label: "Metrics" },
];

const RESPONSES = [
  { id: "ARE-001", incident: "Ransomware detection on file server", severity: "critical", playbook: "isolate-host", status: "executing", actions: 3 },
  { id: "ARE-002", incident: "Brute force attack on VPN gateway", severity: "high", playbook: "block-ip", status: "validating", actions: 2 },
  { id: "ARE-003", incident: "Suspicious API key usage in production", severity: "high", playbook: "revoke-credentials", status: "completed", actions: 4 },
  { id: "ARE-004", incident: "Lateral movement via compromised service account", severity: "critical", playbook: "isolate-host", status: "executing", actions: 5 },
  { id: "ARE-005", incident: "Malware detected in container image", severity: "medium", playbook: "quarantine-file", status: "completed", actions: 2 },
];

const EXECUTIONS = [
  { id: "EX-001", response: "ARE-001", action: "Isolate host from network", status: "completed", duration: "12s" },
  { id: "EX-002", response: "ARE-001", action: "Block C2 IP at firewall", status: "completed", duration: "3s" },
  { id: "EX-003", response: "ARE-001", action: "Capture forensic snapshot", status: "running", duration: "45s" },
  { id: "EX-004", response: "ARE-002", action: "Block source IP 203.0.113.42", status: "completed", duration: "2s" },
  { id: "EX-005", response: "ARE-002", action: "Reset affected user credentials", status: "pending", duration: "-" },
  { id: "EX-006", response: "ARE-004", action: "Disable service account", status: "completed", duration: "4s" },
];

export default function AutonomousResponseEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Autonomous Response Engine" subtitle="Automated incident response with playbook orchestration and validation" icon={<Bot className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Responses" value="3" icon={<Siren className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Threats Contained" value="47" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Avg MTTR" value="38s" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Auto-Resolved" value="92%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Response by Severity</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "8", c: "text-red-400" }, { l: "High", v: "19", c: "text-yellow-400" }, { l: "Medium", v: "14", c: "text-cyan-400" }, { l: "Low", v: "6", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "active_responses" && (<div className="space-y-3">{RESPONSES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.playbook}</span></div><StatusBadge status={r.severity} /></div><p className="text-white/90 text-sm">{r.incident}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><StatusBadge status={r.status} /><span>{r.actions} actions</span></div></div>))}</div>)}
      {tab === "playbook_execution" && (<div className="space-y-3">{EXECUTIONS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.response}</span></div><StatusBadge status={e.status} /></div><p className="text-white/90 text-sm">{e.action}</p><span className="text-xs text-white/50">Duration: {e.duration}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Response Performance</h3>{[{ m: "Mean Time to Respond", v: "38s", t: "-12s" }, { m: "Auto-Resolution Rate", v: "92%", t: "+4%" }, { m: "False Positive Rate", v: "3%", t: "-1%" }, { m: "Containment Success", v: "98%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
