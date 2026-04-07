import { useState } from "react";
import { DollarSign, TrendingUp, AlertTriangle, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "cost_anomalies" | "spend_trends" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "cost_anomalies", label: "Cost Anomalies" },
  { id: "spend_trends", label: "Spend Trends" },
  { id: "metrics", label: "Metrics" },
];

const ANOMALIES = [
  { id: "CA-001", type: "Spike", service: "BigQuery (GCP)", severity: "critical", detail: "Spend increased 340% — 42.5 TB scanned vs 8 TB baseline, $8,500/day" },
  { id: "CA-002", type: "Waste", service: "EC2 (AWS)", severity: "high", detail: "14 idle m5.2xlarge instances in us-east-1, $4,200/mo wasted" },
  { id: "CA-003", type: "Orphan Resource", service: "Cosmos DB (Azure)", severity: "medium", detail: "5,000 RU/s provisioned, <100 RU/s actual usage — 98% idle" },
  { id: "CA-004", type: "Reserved Unused", service: "RDS (AWS)", severity: "high", detail: "3 reserved db.r6g.xlarge unused for 45 days, $1,890/mo" },
];

export default function CloudCostAnomalyDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Cost Anomaly Detector" subtitle="Multi-cloud billing anomaly detection and alerting" icon={<DollarSign className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Monthly Spend" value="$284K" icon={<DollarSign className="h-5 w-5" />} />
        <MetricCard title="Anomalies Detected" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Potential Savings" value="$38K" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Alerts Sent" value="8" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Spend by Provider</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "AWS", v: "$142K", c: "text-orange-400" }, { l: "GCP", v: "$87K", c: "text-blue-400" }, { l: "Azure", v: "$48K", c: "text-cyan-400" }, { l: "Savings Found", v: "$38K", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "cost_anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-white/90 font-medium">{a.type}</span></div><StatusBadge status={a.severity} /></div><p className="text-white/70 text-sm font-mono">{a.service}</p><p className="text-white/50 text-xs mt-1">{a.detail}</p></div>))}</div>)}
      {tab === "spend_trends" && (<div className="card-surface p-6"><h3 className="section-heading">30-Day Trends</h3><div className="space-y-3">{[{ s: "BigQuery", d: "+340%", t: "$8,500/day" }, { s: "EC2", d: "+25%", t: "$4,200/mo" }, { s: "Virtual Machines", d: "+12%", t: "$5,600/mo" }, { s: "Cosmos DB", d: "-5%", t: "$2,400/mo" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.s}</p><p className="text-xs text-white/50">Delta: {x.d}</p></div><span className="text-cyan-400 font-mono">{x.t}</span></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detection Performance</h3>{[{ m: "Anomaly Detection Rate", v: "96.2%", t: "+1.4%" }, { m: "False Positive Rate", v: "2.1%", t: "-0.5%" }, { m: "Avg Alert Latency", v: "4.2min", t: "-1.8min" }, { m: "Auto-Remediation", v: "34%", t: "+8%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
