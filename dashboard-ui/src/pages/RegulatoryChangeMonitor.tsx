import { useState } from "react";
import { Scale, FileText, AlertTriangle, Shield, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "regulatory_changes" | "impact_assessment" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "regulatory_changes", label: "Regulatory Changes" },
  { id: "impact_assessment", label: "Impact Assessment" },
  { id: "metrics", label: "Metrics" },
];

const CHANGES = [
  { id: "RC-001", title: "NIST CSF 2.0 — Govern function added", framework: "NIST CSF", type: "Major Update", impact: "high", effective: "2025-02-26" },
  { id: "RC-002", title: "GDPR AI Act integration guidance", framework: "GDPR", type: "Guidance", impact: "medium", effective: "2025-08-01" },
  { id: "RC-003", title: "PCI DSS 4.0.1 — MFA requirements update", framework: "PCI DSS", type: "Amendment", impact: "critical", effective: "2025-03-31" },
  { id: "RC-004", title: "HIPAA Security Rule — ePHI encryption mandate", framework: "HIPAA", type: "New Requirement", impact: "high", effective: "2025-12-01" },
];

const IMPACTS = [
  { id: "IA-001", change: "RC-003", controls: 8, gaps: 3, effort: "120h", status: "action_required" },
  { id: "IA-002", change: "RC-001", controls: 14, gaps: 5, effort: "200h", status: "in_progress" },
  { id: "IA-003", change: "RC-004", controls: 6, gaps: 2, effort: "80h", status: "action_required" },
  { id: "IA-004", change: "RC-002", controls: 4, gaps: 0, effort: "20h", status: "compliant" },
];

export default function RegulatoryChangeMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Regulatory Change Monitor" subtitle="Regulatory change tracking and impact assessment" icon={<Scale className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Changes" value="12" icon={<FileText className="h-5 w-5" />} />
        <MetricCard title="Control Gaps" value="10" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Frameworks Tracked" value="8" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Actions Generated" value="34" icon={<Target className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Framework Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "NIST", v: "94%", c: "text-emerald-400" }, { l: "GDPR", v: "87%", c: "text-cyan-400" }, { l: "HIPAA", v: "91%", c: "text-emerald-400" }, { l: "PCI DSS", v: "76%", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "regulatory_changes" && (<div className="space-y-3">{CHANGES.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-xs text-white/40">{c.framework}</span></div><StatusBadge status={c.impact} /></div><p className="text-white/90 text-sm">{c.title}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Type: {c.type}</span><span>Effective: {c.effective}</span></div></div>))}</div>)}
      {tab === "impact_assessment" && (<div className="space-y-3">{IMPACTS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.change}</span></div><StatusBadge status={a.status} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Controls: {a.controls}</span><span className={a.gaps > 0 ? "text-yellow-400" : "text-emerald-400"}>{a.gaps} gaps</span><span>Effort: {a.effort}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Monitoring Performance</h3>{[{ m: "Avg Response Time", v: "4.2 days", t: "-1.5 days" }, { m: "Change Detection Rate", v: "97%", t: "+3%" }, { m: "Control Mapping Accuracy", v: "92%", t: "+4%" }, { m: "Action Completion Rate", v: "85%", t: "+7%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
