import { useState } from "react";
import { Users, Target, AlertTriangle, BookOpen, BarChart3, Shield } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "campaigns" | "user_scores" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "campaigns", label: "Campaigns" },
  { id: "user_scores", label: "User Scores" },
  { id: "metrics", label: "Metrics" },
];

const CAMPAIGNS = [
  { name: "Q1 Phishing Simulation", type: "Phishing", targets: 240, clickRate: "18%", status: "active", detail: "Executive spear-phishing with credential harvesting" },
  { name: "Compliance Refresher — HIPAA", type: "Compliance", targets: 85, clickRate: "N/A", status: "active", detail: "Annual HIPAA training for healthcare teams" },
  { name: "Social Engineering Test", type: "Social Eng.", targets: 120, clickRate: "32%", status: "completed", detail: "Pretexting and vishing simulations for finance" },
  { name: "Password Hygiene Workshop", type: "Quiz", targets: 350, clickRate: "N/A", status: "scheduled", detail: "Interactive password strength and MFA awareness" },
];

const TEAM_SCORES = [
  { team: "Engineering", score: 82, clickRate: "12%", risk: "low", trend: "+8" },
  { team: "Finance", score: 54, clickRate: "35%", risk: "high", trend: "-2" },
  { team: "Marketing", score: 68, clickRate: "22%", risk: "medium", trend: "+5" },
  { team: "Executive", score: 45, clickRate: "42%", risk: "critical", trend: "-10" },
  { team: "HR", score: 71, clickRate: "19%", risk: "medium", trend: "+3" },
];

export default function SecurityTrainingPlatform() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Training Platform" subtitle="Security awareness training and phishing simulation" icon={<BookOpen className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Campaigns" value="3" icon={<Target className="h-5 w-5" />} />
        <MetricCard title="Users Trained" value="795" icon={<Users className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Click Rate" value="18%" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="High-Risk Users" value="24" icon={<Shield className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Awareness by Department</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Engineering", v: "82/100", c: "text-emerald-400" }, { l: "Finance", v: "54/100", c: "text-red-400" }, { l: "Marketing", v: "68/100", c: "text-yellow-400" }, { l: "Executive", v: "45/100", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "campaigns" && (<div className="space-y-3">{CAMPAIGNS.map((c, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium">{c.name}</span><span className="ml-2 text-xs text-white/40">{c.type}</span></div><StatusBadge status={c.status === "active" ? "medium" : c.status === "completed" ? "low" : "info"} /></div><p className="text-white/50 text-sm">{c.detail}</p><div className="flex gap-4 mt-1 text-xs text-white/40"><span>Targets: {c.targets}</span><span>Click Rate: {c.clickRate}</span></div></div>))}</div>)}
      {tab === "user_scores" && (<div className="space-y-3">{TEAM_SCORES.map((t, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><span className="text-white/90 font-medium">{t.team}</span><div className="flex gap-4 mt-1 text-xs text-white/40"><span>Score: {t.score}/100</span><span>Click Rate: {t.clickRate}</span><span className={Number(t.trend) > 0 ? "text-emerald-400" : "text-red-400"}>{t.trend}pts</span></div></div><StatusBadge status={t.risk} /></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Training Metrics</h3>{[{ m: "Overall Awareness Score", v: "67/100", t: "+4 vs last quarter" }, { m: "Phishing Click Rate", v: "18%", t: "-7% improvement" }, { m: "Compliance Completion", v: "89%", t: "+3%" }, { m: "Report Rate", v: "42%", t: "+12% improvement" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
