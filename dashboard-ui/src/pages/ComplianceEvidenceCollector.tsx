import { useState } from "react";
import { ClipboardCheck, FileCheck, Layers, BarChart3, Shield, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "evidence_library" | "control_mapping" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "evidence_library", label: "Evidence Library" },
  { id: "control_mapping", label: "Control Mapping" },
  { id: "metrics", label: "Metrics" },
];

const EVIDENCE = [
  { control: "CC6.1 — Logical Access", framework: "SOC2", type: "Audit Log", status: "low", detail: "IAM policy snapshots, access reviews collected 2 days ago" },
  { control: "A.9.1 — Access Control", framework: "ISO 27001", type: "Config Snapshot", status: "low", detail: "RBAC configuration, MFA enforcement evidence validated" },
  { control: "164.312(a)(1) — Access Control", framework: "HIPAA", type: "System Log", status: "medium", detail: "Unique user ID logs present, session timeout evidence pending" },
  { control: "CC7.1 — System Operations", framework: "SOC2", type: "Monitoring Report", status: "low", detail: "Alerting configs, incident response logs, change detection" },
  { control: "Req 10 — Track Access", framework: "PCI-DSS", type: "Audit Trail", status: "critical", detail: "Audit trail incomplete — missing 3 sub-requirements" },
];

export default function ComplianceEvidenceCollector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Compliance Evidence Collector" subtitle="Automated compliance evidence gathering and audit preparation" icon={<ClipboardCheck className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Controls Tracked" value="186" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Evidence Collected" value="412" icon={<FileCheck className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Coverage" value="91.4%" icon={<Layers className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Gaps Found" value="7" icon={<AlertTriangle className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Framework Readiness</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "SOC2", v: "94%", c: "text-emerald-400" }, { l: "ISO 27001", v: "91%", c: "text-cyan-400" }, { l: "HIPAA", v: "87%", c: "text-yellow-400" }, { l: "PCI-DSS", v: "82%", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "evidence_library" && (<div className="space-y-3">{EVIDENCE.map((e) => (<div key={e.control} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium text-sm">{e.control}</span><span className="ml-2 text-xs text-white/40">{e.framework}</span></div><StatusBadge status={e.status} /></div><p className="text-white/50 text-sm">{e.detail}</p><span className="text-xs text-white/40">Type: {e.type}</span></div>))}</div>)}
      {tab === "control_mapping" && (<div className="card-surface p-6"><h3 className="section-heading">Cross-Framework Mapping</h3><div className="space-y-2">{[{ control: "Logical Access Controls", frameworks: "SOC2 CC6.1, ISO A.9.1, HIPAA 164.312, PCI Req 7", coverage: "94%", status: "low" }, { control: "Change Management", frameworks: "SOC2 CC8.1, ISO A.12.1, PCI Req 6", coverage: "91%", status: "low" }, { control: "Incident Response", frameworks: "SOC2 CC7.1, ISO A.16.1, HIPAA 164.308", coverage: "88%", status: "medium" }, { control: "Audit Logging", frameworks: "SOC2 CC7.1, ISO A.12.4, PCI Req 10", coverage: "78%", status: "high" }].map((c, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70">{c.control}</span><p className="text-xs text-white/40 mt-1">{c.frameworks}</p></div><div className="flex gap-3"><span className="text-cyan-400 font-mono">{c.coverage}</span><StatusBadge status={c.status} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Collection Metrics</h3>{[{ m: "Auto-Collection Rate", v: "78.4%", t: "+6.2% vs last quarter" }, { m: "Evidence Freshness", v: "4.2 days avg", t: "-1.8 days" }, { m: "Validation Pass Rate", v: "96.1%", t: "+1.3%" }, { m: "Audit Prep Time", v: "3.2 hours", t: "-2.1 hours saved" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
