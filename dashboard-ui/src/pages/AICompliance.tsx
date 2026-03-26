import { useState } from "react";
import { Scale, FileCheck, AlertCircle, CheckCircle, FileText, Globe } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "systems" | "frameworks" | "evidence";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "systems", label: "AI Systems" }, { id: "frameworks", label: "Frameworks" }, { id: "evidence", label: "Evidence" }];
export default function AICompliance() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="AI Compliance" subtitle="EU AI Act, NIST AI RMF, and ISO 42001 automated compliance" icon={<Scale className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="AI Systems Tracked" value="18" icon={<FileCheck className="h-5 w-5" />} />
      <MetricCard title="Compliance Score" value="87.4%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Open Gaps" value="9" icon={<AlertCircle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Evidence Packages" value="42" icon={<FileText className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Compliance Posture by Framework</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "EU AI Act", score: "84%", color: "text-yellow-400", icon: <Globe className="h-5 w-5" /> },
        { label: "NIST AI RMF", score: "91%", color: "text-emerald-400", icon: <FileCheck className="h-5 w-5" /> },
        { label: "ISO 42001", score: "87%", color: "text-cyan-400", icon: <Scale className="h-5 w-5" /> }].map((f) => (
        <div key={f.label} className="card-interactive p-4 text-center"><div className="flex justify-center mb-2 text-white/40">{f.icon}</div><p className="text-sm text-white/60">{f.label}</p><p className={clsx("text-3xl font-bold mt-1", f.color)}>{f.score}</p></div>))}</div></div>)}
    {tab === "systems" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">AI System</th><th className="px-4 py-3">Risk Tier</th><th className="px-4 py-3">EU AI Act</th><th className="px-4 py-3">NIST RMF</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "Customer Chatbot", tier: "high_risk", euAct: "partial", nist: "compliant", status: "review" },
        { name: "Fraud Detection ML", tier: "high_risk", euAct: "compliant", nist: "compliant", status: "compliant" },
        { name: "Internal Copilot", tier: "limited_risk", euAct: "compliant", nist: "partial", status: "compliant" },
        { name: "Hiring Screener", tier: "high_risk", euAct: "non_compliant", nist: "partial", status: "action_required" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{s.name}</td><td className="px-4 py-3"><StatusBadge status={s.tier} /></td><td className="px-4 py-3"><StatusBadge status={s.euAct} /></td><td className="px-4 py-3"><StatusBadge status={s.nist} /></td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "frameworks" && (<div className="space-y-4">
      {[{ framework: "EU AI Act", articles: [
          { id: "Art. 6", name: "Classification Rules", status: "compliant" },
          { id: "Art. 9", name: "Risk Management System", status: "partial" },
          { id: "Art. 10", name: "Data Governance", status: "compliant" },
          { id: "Art. 13", name: "Transparency", status: "non_compliant" },
          { id: "Art. 14", name: "Human Oversight", status: "partial" },
        ]},
        { framework: "NIST AI RMF", articles: [
          { id: "GOVERN", name: "Governance & Culture", status: "compliant" },
          { id: "MAP", name: "Context & Risk Mapping", status: "compliant" },
          { id: "MEASURE", name: "Risk Measurement", status: "partial" },
          { id: "MANAGE", name: "Risk Management", status: "compliant" },
        ]},
      ].map((fw) => (<div key={fw.framework} className="card-surface p-4"><h4 className="text-white/90 font-medium mb-3">{fw.framework}</h4>
        <div className="space-y-2">{fw.articles.map((a) => (<div key={a.id} className="flex items-center justify-between p-2 rounded bg-white/5"><div><span className="font-mono text-xs text-cyan-400 mr-2">{a.id}</span><span className="text-white/80 text-sm">{a.name}</span></div><StatusBadge status={a.status} /></div>))}</div></div>))}</div>)}
    {tab === "evidence" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Evidence Packages</h3>
      {[{ id: "EVD-042", system: "Fraud Detection ML", framework: "EU AI Act Art. 9", type: "Risk Assessment", date: "2026-03-24", status: "accepted" },
        { id: "EVD-041", system: "Customer Chatbot", framework: "NIST AI RMF GOVERN", type: "Policy Documentation", date: "2026-03-23", status: "accepted" },
        { id: "EVD-040", system: "Hiring Screener", framework: "EU AI Act Art. 14", type: "Human Oversight Plan", date: "2026-03-22", status: "rejected" },
      ].map((e) => (<div key={e.id} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{e.type}</p><p className="text-xs text-white/50">{e.system} | {e.framework} | {e.date}</p></div><StatusBadge status={e.status} /></div>))}</div>)}
  </div>);
}
