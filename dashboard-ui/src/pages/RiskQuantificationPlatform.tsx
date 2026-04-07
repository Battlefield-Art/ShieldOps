import { useState } from "react";
import { Scale, DollarSign, Shield, AlertTriangle, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "risk_scenarios" | "loss_models" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "risk_scenarios", label: "Risk Scenarios" },
  { id: "loss_models", label: "Loss Models" },
  { id: "metrics", label: "Metrics" },
];

const SCENARIOS = [
  { id: "RS-001", asset: "Customer Database", threat: "Ransomware", ale: "$2.4M", tier: "critical", confidence: 0.87 },
  { id: "RS-002", asset: "Payment Gateway", threat: "Data Breach", ale: "$1.8M", tier: "high", confidence: 0.82 },
  { id: "RS-003", asset: "CI/CD Pipeline", threat: "Supply Chain", ale: "$950K", tier: "high", confidence: 0.75 },
  { id: "RS-004", asset: "Email System", threat: "BEC Fraud", ale: "$420K", tier: "medium", confidence: 0.91 },
];

const MODELS = [
  { id: "LM-001", category: "Fines & Judgments", primary: "$1.2M", secondary: "$800K", pct: 35 },
  { id: "LM-002", category: "Productivity Loss", primary: "$600K", secondary: "$200K", pct: 22 },
  { id: "LM-003", category: "Reputation", primary: "$0", secondary: "$1.5M", pct: 28 },
  { id: "LM-004", category: "Response Costs", primary: "$450K", secondary: "$150K", pct: 15 },
];

export default function RiskQuantificationPlatform() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Risk Quantification Platform" subtitle="FAIR methodology cyber risk quantification" icon={<Scale className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total ALE" value="$5.6M" icon={<DollarSign className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Risk Scenarios" value="24" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Assets Analyzed" value="156" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Confidence" value="84%" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Distribution by Tier</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "3", c: "text-red-400" }, { l: "High", v: "8", c: "text-orange-400" }, { l: "Medium", v: "9", c: "text-yellow-400" }, { l: "Low", v: "4", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "risk_scenarios" && (<div className="space-y-3">{SCENARIOS.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.asset}</span></div><StatusBadge status={s.tier} /></div><p className="text-white/90 text-sm">{s.threat}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className="text-red-400 font-mono">ALE: {s.ale}</span><span>Confidence: {Math.round(s.confidence * 100)}%</span></div></div>))}</div>)}
      {tab === "loss_models" && (<div className="space-y-3">{MODELS.map((m) => (<div key={m.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{m.id}</span><span className="text-xs text-white/40">{m.pct}% of total</span></div><p className="text-white/90 text-sm font-medium">{m.category}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Primary: {m.primary}</span><span>Secondary: {m.secondary}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">FAIR Metrics</h3>{[{ m: "Total ALE", v: "$5.6M", t: "+$400K" }, { m: "Risk Scenarios", v: "24", t: "+3" }, { m: "Avg Loss Event Freq", v: "0.34/yr", t: "-0.02" }, { m: "Model Accuracy", v: "84%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
