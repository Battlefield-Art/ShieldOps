import { useState } from "react";
import { Brain, Shield, AlertTriangle, Scale, CheckCircle, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "model_registry" | "compliance_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "model_registry", label: "Model Registry" },
  { id: "compliance_status", label: "Compliance Status" },
  { id: "metrics", label: "Metrics" },
];

const MODELS = [
  { name: "fraud-detector-v3", framework: "PyTorch", risk: "high", bias: "critical", compliance: "EU AI Act", status: "non-compliant" },
  { name: "recommendation-engine", framework: "TensorFlow", risk: "limited", bias: "low", compliance: "NIST AI RMF", status: "compliant" },
  { name: "credit-scoring-v2", framework: "sklearn", risk: "high", bias: "high", compliance: "EU AI Act", status: "non-compliant" },
  { name: "nlp-classifier", framework: "HuggingFace", risk: "minimal", bias: "low", compliance: "ISO 42001", status: "compliant" },
  { name: "demand-forecast", framework: "PyTorch", risk: "limited", bias: "medium", compliance: "NIST AI RMF", status: "compliant" },
];

export default function AIModelGovernance() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="AI Model Governance" subtitle="Lifecycle governance, bias detection, and regulatory compliance for AI models" icon={<Brain className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Models Governed" value="142" icon={<Brain className="h-5 w-5" />} />
        <MetricCard title="High Risk" value="18" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Bias Detected" value="7" icon={<Scale className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Compliant" value="89%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Tier Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Unacceptable", v: "2", c: "text-red-400" }, { l: "High", v: "18", c: "text-orange-400" }, { l: "Limited", v: "47", c: "text-yellow-400" }, { l: "Minimal", v: "75", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "model_registry" && (<div className="space-y-3">{MODELS.map((m) => (<div key={m.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{m.name}</span><span className="ml-2 text-xs text-white/40">{m.framework}</span></div><StatusBadge status={m.risk} /></div><div className="flex gap-4 text-sm"><span className="text-white/50">Bias: <span className={clsx(m.bias === "critical" ? "text-red-400" : m.bias === "high" ? "text-orange-400" : "text-white/70")}>{m.bias}</span></span><span className="text-white/50">Framework: {m.compliance}</span><StatusBadge status={m.status === "compliant" ? "low" : "high"} /></div></div>))}</div>)}
      {tab === "compliance_status" && (<div className="card-surface p-6"><h3 className="section-heading">Regulatory Compliance</h3><div className="space-y-2">{[{ fw: "EU AI Act", compliant: 82, total: 100, status: "high" }, { fw: "NIST AI RMF", compliant: 91, total: 100, status: "low" }, { fw: "ISO 42001", compliant: 76, total: 100, status: "high" }].map((f) => (<div key={f.fw} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70">{f.fw}</span><div className="flex gap-3 items-center"><span className="text-white/40">{f.compliant}/{f.total} controls</span><div className="w-24 h-2 rounded-full bg-white/10"><div className="h-full rounded-full bg-cyan-400" style={{ width: `${f.compliant}%` }} /></div><StatusBadge status={f.status} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Governance Trends</h3>{[{ m: "Models Audited (30d)", v: "142", t: "+8 this month" }, { m: "Avg Risk Score", v: "34.2/100", t: "-2.1 vs last month" }, { m: "Bias Incidents", v: "3", t: "-2 vs last quarter" }, { m: "Policy Enforcements", v: "12", t: "+4 this week" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
