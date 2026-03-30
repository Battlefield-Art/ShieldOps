import { useState } from "react";
import { BookOpen, Users, AlertTriangle, CheckCircle, Target, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "training" | "phishing" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "training", label: "Training" },
  { id: "phishing", label: "Phishing Sims" },
  { id: "metrics", label: "Metrics" },
];

const TRAINING = [
  { module: "Phishing Awareness", completion: 92, enrolled: 450, status: "active" },
  { module: "Password Hygiene", completion: 87, enrolled: 450, status: "active" },
  { module: "Data Handling", completion: 78, enrolled: 320, status: "active" },
  { module: "Incident Reporting", completion: 95, enrolled: 450, status: "active" },
  { module: "Social Engineering", completion: 64, enrolled: 200, status: "in_progress" },
];

const PHISHING = [
  { id: "SIM-001", campaign: "Q1 Credential Harvest", sent: 450, clicked: 34, reported: 380, status: "completed" },
  { id: "SIM-002", campaign: "Fake Invoice Attack", sent: 300, clicked: 18, reported: 260, status: "completed" },
  { id: "SIM-003", campaign: "CEO Impersonation", sent: 150, clicked: 12, reported: 120, status: "active" },
];

export default function SecurityAwarenessEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Awareness Engine" subtitle="Training management and phishing simulation analytics" icon={<BookOpen className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Employees" value="450" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Training Complete" value="87%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Phish Click Rate" value="7.5%" icon={<Target className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Risk Score" value="Low" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Awareness Posture</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Low Risk", v: "340", c: "text-emerald-400" }, { l: "Moderate", v: "78", c: "text-yellow-400" }, { l: "High Risk", v: "27", c: "text-orange-400" }, { l: "Critical", v: "5", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "training" && (<div className="space-y-3">{TRAINING.map((t) => (<div key={t.module} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{t.module}</span><StatusBadge status={t.status} /></div><div className="flex items-center gap-4 text-sm"><span className="text-white/50">{t.enrolled} enrolled</span><div className="flex-1"><div className="h-2 rounded-full bg-white/10 overflow-hidden"><div className="h-full rounded-full bg-emerald-500" style={{ width: `${t.completion}%` }} /></div></div><span className="text-white/70 font-mono text-xs">{t.completion}%</span></div></div>))}</div>)}
      {tab === "phishing" && (<div className="space-y-3">{PHISHING.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 text-white/90 font-medium">{p.campaign}</span></div><StatusBadge status={p.status} /></div><div className="flex gap-4 text-sm text-white/50"><span>Sent: {p.sent}</span><span className="text-yellow-400">Clicked: {p.clicked} ({((p.clicked/p.sent)*100).toFixed(1)}%)</span><span className="text-emerald-400">Reported: {p.reported}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Awareness Trends</h3>{[{ m: "Training Completion", v: "87%", t: "+5%" }, { m: "Phish Click Rate", v: "7.5%", t: "-2.3%" }, { m: "Report Rate", v: "84%", t: "+8%" }, { m: "Risk Score", v: "Low", t: "Down from Moderate" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
