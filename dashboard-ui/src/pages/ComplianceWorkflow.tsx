import { useState } from "react";
import { ShieldCheck, FileCheck, AlertTriangle, CheckCircle, ClipboardList, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "controls" | "gaps" | "remediation";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "controls", label: "Controls" }, { id: "gaps", label: "Gaps" }, { id: "remediation", label: "Remediation" }];
export default function ComplianceWorkflow() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Compliance Workflow" subtitle="End-to-end audit automation — evidence collection, control testing, gap remediation" icon={<ShieldCheck className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Controls Tested" value="142" icon={<ClipboardList className="h-5 w-5" />} />
      <MetricCard title="Compliance Score" value="87.3%" icon={<BarChart3 className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Open Gaps" value="18" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Evidence Items" value="426" icon={<FileCheck className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Framework Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ fw: "SOC 2", score: "92%", controls: 64, gaps: 5, color: "text-emerald-400" }, { fw: "HIPAA", score: "88%", controls: 42, gaps: 5, color: "text-cyan-400" }, { fw: "PCI DSS", score: "79%", controls: 36, gaps: 8, color: "text-yellow-400" }].map((f) => (
        <div key={f.fw} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{f.fw}</p><p className={clsx("text-2xl font-bold mt-1", f.color)}>{f.score}</p><p className="text-xs text-white/40">{f.controls} controls | {f.gaps} gaps</p></div>))}</div></div>)}
    {tab === "controls" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Control ID</th><th className="px-4 py-3">Name</th><th className="px-4 py-3">Framework</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Evidence</th></tr></thead>
      <tbody>{[
        { id: "CC6.1", name: "Logical Access", fw: "SOC 2", status: "passing", evidence: 3 },
        { id: "CC7.1", name: "System Operations", fw: "SOC 2", status: "passing", evidence: 4 },
        { id: "§164.312(a)", name: "Access Control", fw: "HIPAA", status: "partially_passing", evidence: 2 },
        { id: "PCI-3.1", name: "Data Protection", fw: "PCI DSS", status: "failing", evidence: 1 },
        { id: "CC8.1", name: "Change Management", fw: "SOC 2", status: "passing", evidence: 3 },
        { id: "§164.312(e)", name: "Transmission Security", fw: "HIPAA", status: "passing", evidence: 2 },
      ].map((c, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-mono text-xs">{c.id}</td><td className="px-4 py-3 text-white/80">{c.name}</td><td className="px-4 py-3 text-white/60">{c.fw}</td><td className="px-4 py-3"><StatusBadge status={c.status} /></td><td className="px-4 py-3 text-white/60">{c.evidence} items</td></tr>))}</tbody></table></div>)}
    {tab === "gaps" && (<div className="space-y-3">
      {[{ id: "GAP-001", control: "PCI-3.1", severity: "high", desc: "Stored cardholder data lacks AES-256 encryption at rest", status: "open" },
        { id: "GAP-002", control: "§164.312(a)", severity: "medium", desc: "MFA not enforced for all ePHI access paths", status: "in_progress" },
        { id: "GAP-003", control: "CC3.1", severity: "medium", desc: "Risk assessment not updated in 12+ months", status: "open" },
        { id: "GAP-004", control: "PCI-10.1", severity: "high", desc: "Audit log retention below 12-month PCI requirement", status: "remediated" },
      ].map((g, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium">{g.desc}</p><p className="text-xs text-white/50 mt-1">{g.id} | Control: {g.control} | Severity: {g.severity}</p></div><StatusBadge status={g.status} /></div></div>))}</div>)}
    {tab === "remediation" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Remediation Tracker</h3>
      {[{ gap: "GAP-001", action: "Enable AES-256 encryption for cardholder data stores", owner: "Platform Team", due: "2026-04-15", status: "in_progress" },
        { gap: "GAP-002", action: "Enforce MFA on all ePHI access endpoints", owner: "Identity Team", due: "2026-04-10", status: "in_progress" },
        { gap: "GAP-003", action: "Complete annual risk assessment update", owner: "GRC Team", due: "2026-04-20", status: "pending" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.gap} | Owner: {r.owner} | Due: {r.due}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
