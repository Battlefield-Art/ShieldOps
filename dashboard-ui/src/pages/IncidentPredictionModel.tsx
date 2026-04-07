import { useState } from "react";
import { TrendingUp, AlertTriangle, Activity, Brain, Gauge } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "predictions" | "risk_forecast" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "predictions", label: "Predictions" },
  { id: "risk_forecast", label: "Risk Forecast" },
  { id: "metrics", label: "Metrics" },
];

const PREDICTIONS = [
  { id: "PR-001", type: "Ransomware", probability: 0.87, risk: "critical", horizon: "8h", detail: "Failed login spike + outbound data anomaly + weekend access pattern" },
  { id: "PR-002", type: "Credential Compromise", probability: 0.74, risk: "high", horizon: "12h", detail: "Privilege escalation attempts + DNS entropy increase + new process creation" },
  { id: "PR-003", type: "Data Breach", probability: 0.62, risk: "high", horizon: "24h", detail: "Outbound volume 4x baseline + CPU anomaly + alert frequency spike" },
  { id: "PR-004", type: "DDoS Attack", probability: 0.45, risk: "medium", horizon: "48h", detail: "Traffic pattern shifts + bandwidth anomaly indicators" },
];

export default function IncidentPredictionModel() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Incident Prediction Model" subtitle="ML-based security incident prediction and early warning system" icon={<Brain className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Leading Indicators" value="128" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Active Predictions" value="6" icon={<TrendingUp className="h-5 w-5 text-amber-400" />} />
        <MetricCard title="Model Confidence" value="87%" icon={<Gauge className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Warnings Issued" value="4" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Prediction Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical Risk", v: "1", c: "text-red-500" }, { l: "High Risk", v: "2", c: "text-red-400" }, { l: "Medium Risk", v: "2", c: "text-amber-400" }, { l: "Low Risk", v: "1", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "predictions" && (<div className="space-y-3">{PREDICTIONS.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 text-white/90 font-medium">{p.type}</span><span className="ml-2 text-xs text-white/40">within {p.horizon}</span></div><StatusBadge status={p.risk} /></div><p className="text-white/50 text-xs">{p.detail}</p><div className="mt-2 flex items-center gap-2"><span className="text-xs text-white/40">Probability:</span><div className="flex-1 h-1.5 bg-white/10 rounded-full"><div className="h-1.5 bg-amber-400 rounded-full" style={{ width: `${p.probability * 100}%` }} /></div><span className="text-xs font-mono text-white/60">{(p.probability * 100).toFixed(0)}%</span></div></div>))}</div>)}
      {tab === "risk_forecast" && (<div className="card-surface p-6"><h3 className="section-heading">72-Hour Risk Forecast</h3><div className="space-y-3">{[{ window: "0-8h", risk: "Critical", incidents: "Ransomware likely", color: "text-red-500" }, { window: "8-24h", risk: "High", incidents: "Credential compromise possible", color: "text-red-400" }, { window: "24-48h", risk: "Medium", incidents: "Data breach indicators rising", color: "text-amber-400" }, { window: "48-72h", risk: "Low", incidents: "DDoS pattern forming", color: "text-emerald-400" }].map((f, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.window}</p><p className="text-xs text-white/50">{f.incidents}</p></div><span className={clsx("font-mono font-bold", f.color)}>{f.risk}</span></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Model Performance</h3>{[{ m: "Prediction Accuracy", v: "89%", t: "+2%" }, { m: "False Positive Rate", v: "4.2%", t: "-0.8%" }, { m: "Lead Time (avg)", v: "18h", t: "+3h" }, { m: "Model Version", v: "v1.2", t: "updated 2d ago" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
