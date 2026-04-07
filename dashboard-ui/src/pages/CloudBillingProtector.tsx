import { useState } from "react";
import { DollarSign, Shield, AlertTriangle, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "billing_anomalies" | "fraud_detection" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "billing_anomalies", label: "Billing Anomalies" },
  { id: "fraud_detection", label: "Fraud Detection" },
  { id: "metrics", label: "Metrics" },
];

const ANOMALIES = [
  { id: "BA-001", service: "EC2-GPU", resource: "i-0gpu789xyz000", severity: "critical", detail: "GPU instance with no tags, 2400% cost deviation — cryptomining suspected" },
  { id: "BA-002", service: "EC2", resource: "i-0rogue456abc", severity: "high", detail: "Untagged instance in ap-southeast-1, $6,700 excess spend" },
  { id: "BA-003", service: "RDS", resource: "db-analytics-xl", severity: "medium", detail: "XL instance in staging, 113% over historical average" },
  { id: "BA-004", service: "Lambda", resource: "fn-batch-processor", severity: "medium", detail: "50M invocations in 30 days, 300% above baseline" },
];

export default function CloudBillingProtector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Billing Protector" subtitle="Cloud billing fraud detection, abuse prevention, and budget enforcement" icon={<DollarSign className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Spend Analyzed" value="$31.8K" icon={<DollarSign className="h-5 w-5" />} />
        <MetricCard title="Anomalies Detected" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Fraud Confirmed" value="2" icon={<Shield className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Savings Protected" value="$19.2K" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Spend by Risk</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Normal", v: "$12.5K", c: "text-emerald-400" }, { l: "Suspicious", v: "$5.4K", c: "text-yellow-400" }, { l: "Anomalous", v: "$7.2K", c: "text-orange-400" }, { l: "Fraudulent", v: "$6.7K", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "billing_anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-white/90 font-medium">{a.service}</span></div><StatusBadge status={a.severity} /></div><p className="text-white/70 text-sm font-mono">{a.resource}</p><p className="text-white/50 text-xs mt-1">{a.detail}</p></div>))}</div>)}
      {tab === "fraud_detection" && (<div className="card-surface p-6"><p className="text-white/60">Fraud classification engine analyzing cryptomining, resource hijacking, and credential abuse across 3 cloud accounts.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Protection Metrics</h3>{[{ m: "Detection Accuracy", v: "97.1%", t: "+1.2%" }, { m: "False Positive Rate", v: "1.8%", t: "-0.5%" }, { m: "Avg Detection Time", v: "4.2min", t: "-1.5min" }, { m: "Budget Compliance", v: "92%", t: "+8%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
