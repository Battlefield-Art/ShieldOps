import { useState } from "react";
import { Scale, Shield, AlertTriangle, FileCheck, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "frameworks" | "gaps" | "plans";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "frameworks", label: "Frameworks" }, { id: "gaps", label: "Gaps" }, { id: "plans", label: "Remediation Plans" }];
export default function ComplianceGapAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Compliance Gap Analyzer" subtitle="Map controls to frameworks, find gaps, generate remediation plans" icon={<Scale className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Controls Mapped" value="234" icon={<FileCheck className="h-5 w-5" />} />
      <MetricCard title="Compliance" value="87.2%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Gaps Found" value="30" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Frameworks" value="6" icon={<Target className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Compliance by Framework</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ fw: "SOC 2", pct: 94, gaps: 4, color: "text-emerald-400" }, { fw: "HIPAA", pct: 88, gaps: 8, color: "text-cyan-400" }, { fw: "PCI DSS", pct: 91, gaps: 6, color: "text-emerald-400" }, { fw: "GDPR", pct: 82, gaps: 12, color: "text-yellow-400" }, { fw: "NIST CSF", pct: 86, gaps: 9, color: "text-cyan-400" }, { fw: "ISO 27001", pct: 79, gaps: 14, color: "text-yellow-400" }].map((f) => (
        <div key={f.fw} className="card-interactive p-4"><div className="flex justify-between"><p className="text-white/90 font-medium">{f.fw}</p><p className={clsx("text-2xl font-bold", f.color)}>{f.pct}%</p></div><p className="text-xs text-white/40">{f.gaps} gaps</p></div>))}</div></div>)}
    {tab === "frameworks" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Framework</th><th className="px-4 py-3">Controls</th><th className="px-4 py-3">Implemented</th><th className="px-4 py-3">Partial</th><th className="px-4 py-3">Missing</th></tr></thead>
      <tbody>{[
        { fw: "SOC 2 Type II", total: 64, impl: 60, partial: 3, missing: 1 },
        { fw: "HIPAA", total: 42, impl: 37, partial: 3, missing: 2 },
        { fw: "PCI DSS 4.0", total: 78, impl: 71, partial: 4, missing: 3 },
        { fw: "NIST CSF 2.0", total: 108, impl: 93, partial: 8, missing: 7 },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{f.fw}</td><td className="px-4 py-3 text-white/80">{f.total}</td><td className="px-4 py-3 text-emerald-400">{f.impl}</td><td className="px-4 py-3 text-yellow-400">{f.partial}</td><td className="px-4 py-3 text-red-400">{f.missing}</td></tr>))}</tbody></table></div>)}
    {tab === "gaps" && (<div className="space-y-3">
      {[{ control: "GDPR Art. 17 — Right to Erasure", framework: "GDPR", status: "missing", detail: "No automated data deletion workflow" },
        { control: "NIST PR.DS-1 — Data-at-rest protection", framework: "NIST CSF", status: "partial", detail: "3 databases lack encryption" },
        { control: "PCI DSS 3.4 — Render PAN unreadable", framework: "PCI DSS", status: "partial", detail: "Legacy system stores PAN in clear text" },
      ].map((g, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-xs text-white/40">{g.framework}</span></div><StatusBadge status={g.status} /></div>
        <p className="text-white/90 font-medium">{g.control}</p><p className="text-xs text-white/50">{g.detail}</p></div>))}</div>)}
    {tab === "plans" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Remediation Plans</h3>
      {[{ gap: "GDPR Right to Erasure", plan: "Implement automated data deletion pipeline with 30-day SLA", effort: "High", deadline: "Q2 2026", status: "planned" },
        { gap: "Database encryption", plan: "Enable TDE on 3 remaining PostgreSQL instances", effort: "Medium", deadline: "2 weeks", status: "in_progress" },
        { gap: "PAN tokenization", plan: "Migrate legacy PAN storage to tokenization service", effort: "High", deadline: "Q3 2026", status: "planned" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.gap}</p><p className="text-xs text-white/50">{p.plan} | Effort: {p.effort} | {p.deadline}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
