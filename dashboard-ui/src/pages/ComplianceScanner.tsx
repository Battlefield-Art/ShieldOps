import { useState } from "react";
import { ScanLine, Shield, CheckCircle, AlertTriangle, FileCheck } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "frameworks" | "evidence";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "frameworks", label: "Frameworks" }, { id: "evidence", label: "Evidence" }];
export default function ComplianceScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Compliance Scanner" subtitle="Continuous compliance scanning across regulatory frameworks" icon={<ScanLine className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Controls Scanned" value="485" icon={<Shield className="h-5 w-5" />} />
      <MetricCard title="Findings" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Compliance Score" value="94%" icon={<CheckCircle className="h-5 w-5" />} />
      <MetricCard title="Evidence Items" value="1,847" icon={<FileCheck className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Framework Compliance</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-3">
      {[{ fw: "SOC 2", score: 96 }, { fw: "PCI DSS", score: 93 }, { fw: "HIPAA", score: 91 }, { fw: "GDPR", score: 94 }, { fw: "NIST CSF", score: 89 }].map((f) => (
        <div key={f.fw} className="card-interactive p-3 text-center"><p className="text-xs text-white/50">{f.fw}</p><p className={clsx("text-2xl font-bold mt-1", f.score >= 95 ? "text-emerald-400" : f.score >= 90 ? "text-cyan-400" : "text-yellow-400")}>{f.score}%</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Open Findings</h3>
      {[{ control: "CC6.1 - Access Control", fw: "SOC 2", desc: "Service account with excessive privileges", sev: "high", auto: true },
        { control: "3.4.1 - Cardholder Data", fw: "PCI DSS", desc: "Credit card data not masked in logs", sev: "critical", auto: false },
        { control: "164.312(a) - Access Control", fw: "HIPAA", desc: "PHI accessible without MFA", sev: "high", auto: true },
      ].map((f, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.control} ({f.fw})</p><p className="text-xs text-white/50">{f.desc}</p></div><StatusBadge status={f.sev} /></div>))}</div>)}
    {tab === "frameworks" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scan Schedule</h3>
      {[{ fw: "SOC 2", freq: "Continuous", last: "2 min ago", controls: 64 }, { fw: "PCI DSS", freq: "Daily", last: "6 hr ago", controls: 42 }, { fw: "HIPAA", freq: "Daily", last: "8 hr ago", controls: 54 }].map((f) => (
        <div key={f.fw} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.fw}</p><p className="text-xs text-white/50">{f.controls} controls | {f.freq} | Last: {f.last}</p></div><StatusBadge status="active" /></div>))}</div>)}
    {tab === "evidence" && (<div className="card-surface p-6"><h3 className="section-heading">Evidence Collection</h3><div className="grid grid-cols-2 gap-4">
      {[{ m: "Auto-Collected", v: "1,623 (88%)" }, { m: "Manual Required", v: "224 (12%)" }, { m: "Freshness < 7d", v: "94%" }, { m: "Audit Ready", v: "91%" }].map((s) => (
        <div key={s.m} className="card-interactive p-4"><p className="text-sm text-white/60">{s.m}</p><p className="text-2xl font-bold text-white mt-1">{s.v}</p></div>))}</div></div>)}
  </div>);
}
