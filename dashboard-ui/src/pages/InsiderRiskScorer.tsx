import { useState } from "react";
import { UserX, Users, AlertTriangle, Shield, BarChart3, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "risk_scores" | "behavioral_anomalies" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "risk_scores", label: "Risk Scores" },
  { id: "behavioral_anomalies", label: "Behavioral Anomalies" },
  { id: "metrics", label: "Metrics" },
];

const RISK_SCORES = [
  { user: "alice@corp.com", department: "Engineering", score: 0.92, tier: "critical", factors: 5 },
  { user: "bob@corp.com", department: "DevOps", score: 0.78, tier: "high", factors: 3 },
  { user: "charlie@corp.com", department: "Finance", score: 0.45, tier: "medium", factors: 2 },
  { user: "dana@corp.com", department: "Marketing", score: 0.22, tier: "low", factors: 1 },
];

const ANOMALIES = [
  { id: "ANOM-001", user: "alice@corp.com", category: "Data Movement", description: "750MB bulk export outside business hours", severity: "critical" },
  { id: "ANOM-002", user: "bob@corp.com", category: "Privilege Usage", description: "IAM policy modification on non-owned resources", severity: "high" },
  { id: "ANOM-003", user: "alice@corp.com", category: "Peer Deviation", description: "3x more API calls than peer group average", severity: "high" },
  { id: "ANOM-004", user: "charlie@corp.com", category: "Access Pattern", description: "Login from new geographic location", severity: "medium" },
];

export default function InsiderRiskScorer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Insider Risk Scorer" subtitle="Behavioral analytics and insider risk scoring" icon={<UserX className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Users Monitored" value="1,247" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="High Risk Users" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Anomalies (7d)" value="34" icon={<Activity className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Avg Risk Score" value="0.31" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Distribution</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-4">{[{ l: "Critical", v: "3", c: "text-red-400" }, { l: "High", v: "9", c: "text-orange-400" }, { l: "Medium", v: "28", c: "text-yellow-400" }, { l: "Low", v: "156", c: "text-emerald-400" }, { l: "Minimal", v: "1,051", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "risk_scores" && (<div className="space-y-3">{RISK_SCORES.map((r) => (<div key={r.user} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-sm text-white/90">{r.user}</span><span className="ml-2 text-xs text-white/40">{r.department}</span></div><StatusBadge status={r.tier} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Score: <span className="text-cyan-400 font-mono">{r.score}</span></span><span>{r.factors} contributing factors</span></div></div>))}</div>)}
      {tab === "behavioral_anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.category}</span></div><StatusBadge status={a.severity} /></div><p className="text-white/90 text-sm">{a.description}</p><span className="text-xs text-white/50">{a.user}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scoring Performance</h3>{[{ m: "Users Scored / Day", v: "1,247", t: "+12" }, { m: "Anomaly Detection Rate", v: "94%", t: "+3%" }, { m: "False Positive Rate", v: "8%", t: "-2%" }, { m: "Avg Scoring Latency", v: "1.2s", t: "-0.3s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
