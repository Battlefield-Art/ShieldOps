import { useState } from "react";
import { Mail, Users, Target, Shield } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "campaigns" | "results" | "departments";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "campaigns", label: "Campaigns" }, { id: "results", label: "Results" }, { id: "departments", label: "By Department" }];
export default function PhishingSimulator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Phishing Simulator" subtitle="Employee awareness testing with safe simulated phishing campaigns" icon={<Mail className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Campaigns Run" value="12" icon={<Mail className="h-5 w-5" />} />
      <MetricCard title="Employees Tested" value="645" icon={<Users className="h-5 w-5" />} />
      <MetricCard title="Click Rate" value="12.3%" icon={<Target className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Report Rate" value="67%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Awareness Metrics (Trend)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ metric: "Click Rate", current: "12.3%", previous: "23.1%", trend: "-47%", color: "text-emerald-400" },
        { metric: "Report Rate", current: "67%", previous: "34%", trend: "+97%", color: "text-emerald-400" },
        { metric: "Credential Submit", current: "4.2%", previous: "11.8%", trend: "-64%", color: "text-emerald-400" }].map((m) => (
        <div key={m.metric} className="card-interactive p-4"><p className="text-sm text-white/60">{m.metric}</p><p className="text-2xl font-bold text-white/80 mt-1">{m.current}</p><p className={clsx("text-sm mt-1", m.color)}>{m.trend} vs previous</p></div>))}</div></div>)}
    {tab === "campaigns" && (<div className="space-y-3">
      {[{ id: "PHI-012", name: "IT Password Reset", type: "credential_harvest", sent: 200, clicked: 24, reported: 134, status: "completed" },
        { id: "PHI-011", name: "Urgent Invoice Payment", type: "malware_link", sent: 150, clicked: 18, reported: 98, status: "completed" },
        { id: "PHI-010", name: "Shared Document Access", type: "credential_harvest", sent: 300, clicked: 42, reported: 201, status: "completed" },
      ].map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="text-xs text-white/40 ml-2">{c.type}</span></div><StatusBadge status={c.status} /></div>
        <p className="text-white/90 font-medium">{c.name}</p><p className="text-xs text-white/50">Sent: {c.sent} | Clicked: {c.clicked} ({Math.round(c.clicked/c.sent*100)}%) | Reported: {c.reported} ({Math.round(c.reported/c.sent*100)}%)</p></div>))}</div>)}
    {tab === "results" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Employee Risk Levels</h3>
      {[{ level: "High Risk (clicked + submitted credentials)", count: 27, pct: "4.2%", color: "text-red-400" },
        { level: "Moderate Risk (clicked but didn't submit)", count: 52, pct: "8.1%", color: "text-yellow-400" },
        { level: "Low Risk (opened but didn't click)", count: 134, pct: "20.8%", color: "text-white/60" },
        { level: "Trained (reported as phishing)", count: 432, pct: "67.0%", color: "text-emerald-400" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className={clsx("font-medium", r.color)}>{r.level}</p><p className="text-xs text-white/50">{r.count} employees ({r.pct})</p></div><span className="text-2xl font-bold text-white/80">{r.count}</span></div>))}</div>)}
    {tab === "departments" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Department</th><th className="px-4 py-3">Tested</th><th className="px-4 py-3">Click Rate</th><th className="px-4 py-3">Report Rate</th><th className="px-4 py-3">Risk</th></tr></thead>
      <tbody>{[
        { dept: "Engineering", tested: 120, click: "6.7%", report: "82%", risk: "low" },
        { dept: "Sales", tested: 89, click: "18.0%", report: "45%", risk: "high" },
        { dept: "Finance", tested: 45, click: "22.2%", report: "38%", risk: "critical" },
        { dept: "HR", tested: 34, click: "14.7%", report: "56%", risk: "medium" },
        { dept: "Executive", tested: 12, click: "8.3%", report: "75%", risk: "low" },
      ].map((d, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{d.dept}</td><td className="px-4 py-3 text-white/80">{d.tested}</td><td className="px-4 py-3 text-white/70">{d.click}</td><td className="px-4 py-3 text-white/70">{d.report}</td><td className="px-4 py-3"><StatusBadge status={d.risk} /></td></tr>))}</tbody></table></div>)}
  </div>);
}
