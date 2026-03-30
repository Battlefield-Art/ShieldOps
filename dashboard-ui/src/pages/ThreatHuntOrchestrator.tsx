import { useState } from "react";
import { Crosshair, Search, Shield, AlertTriangle, Target, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "hunts" | "findings" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "hunts", label: "Active Hunts" },
  { id: "findings", label: "Findings" },
  { id: "metrics", label: "Metrics" },
];

const HUNTS = [
  { id: "HNT-001", hypothesis: "APT lateral movement via RDP", type: "Intelligence", tactic: "Lateral Movement", status: "active", findings: 3 },
  { id: "HNT-002", hypothesis: "Credential stuffing on SSO portal", type: "Hypothesis", tactic: "Credential Access", status: "active", findings: 1 },
  { id: "HNT-003", hypothesis: "Supply chain backdoor in npm packages", type: "Situational", tactic: "Initial Access", status: "completed", findings: 0 },
  { id: "HNT-004", hypothesis: "Data staging before exfiltration", type: "Automated", tactic: "Collection", status: "active", findings: 5 },
];

const FINDINGS = [
  { id: "HF-001", hunt: "HNT-001", title: "Unusual RDP connections from service account", severity: "high", mitre: "T1021.001" },
  { id: "HF-002", hunt: "HNT-004", title: "Large archive files created in temp directories", severity: "critical", mitre: "T1560.001" },
  { id: "HF-003", hunt: "HNT-002", title: "Spike in failed SSO attempts from VPN subnet", severity: "medium", mitre: "T1110.004" },
];

export default function ThreatHuntOrchestrator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Threat Hunt Orchestrator" subtitle="Proactive threat hunting with MITRE ATT&CK mapping" icon={<Crosshair className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Hunts" value="4" icon={<Search className="h-5 w-5" />} />
        <MetricCard title="Findings (30d)" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Tactics Covered" value="8/14" icon={<Target className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="True Positive Rate" value="78%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Hunt Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Intelligence", v: "3", c: "text-cyan-400" }, { l: "Hypothesis", v: "5", c: "text-emerald-400" }, { l: "Situational", v: "2", c: "text-yellow-400" }, { l: "Automated", v: "4", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "hunts" && (<div className="space-y-3">{HUNTS.map((h) => (<div key={h.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{h.id}</span><span className="ml-2 text-xs text-white/40">{h.type}</span></div><StatusBadge status={h.status} /></div><p className="text-white/90 text-sm">{h.hypothesis}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Tactic: {h.tactic}</span><span className={h.findings > 0 ? "text-yellow-400" : "text-white/40"}>{h.findings} findings</span></div></div>))}</div>)}
      {tab === "findings" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-xs text-white/40">{f.hunt}</span></div><StatusBadge status={f.severity} /></div><p className="text-white/90 text-sm">{f.title}</p><span className="text-xs text-cyan-400 font-mono">{f.mitre}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Hunt Performance</h3>{[{ m: "True Positive Rate", v: "78%", t: "+6%" }, { m: "Avg Hunt Duration", v: "3.2 days", t: "-0.8 days" }, { m: "Findings per Hunt", v: "1.6", t: "+0.3" }, { m: "MITRE Coverage", v: "57%", t: "+8%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
