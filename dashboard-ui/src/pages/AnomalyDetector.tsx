import { useState } from "react";
import { Activity, AlertTriangle, TrendingUp, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "anomalies" | "baselines" | "alerts";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "anomalies", label: "Anomalies" }, { id: "baselines", label: "Baselines" }, { id: "alerts", label: "Alerts" }];
export default function AnomalyDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Anomaly Detector" subtitle="ML-based anomaly detection across metrics, logs, and traces" icon={<Activity className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Metrics Monitored" value="1,247" icon={<BarChart3 className="h-5 w-5" />} />
      <MetricCard title="Active Anomalies" value="8" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Precision" value="94%" icon={<TrendingUp className="h-5 w-5" />} />
      <MetricCard title="Alerts Fired (24h)" value="12" icon={<Activity className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Anomaly Distribution</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "Spike", count: 3, sev: "critical" }, { type: "Trend Change", count: 3, sev: "high" }, { type: "Seasonal Deviation", count: 2, sev: "medium" }].map((a) => (
        <div key={a.type} className="card-interactive p-4"><p className="text-sm text-white/60">{a.type}</p><p className="text-2xl font-bold text-white mt-1">{a.count}</p><StatusBadge status={a.sev} /></div>))}</div></div>)}
    {tab === "anomalies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Anomalies</h3>
      {[{ metric: "api-gateway.p99_latency", type: "Spike", baseline: "180ms", current: "890ms", sigma: 4.2, sev: "critical" },
        { metric: "billing.error_rate", type: "Trend Change", baseline: "0.1%", current: "1.8%", sigma: 3.1, sev: "high" },
        { metric: "worker.cpu_usage", type: "Seasonal", baseline: "45%", current: "92%", sigma: 2.8, sev: "high" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium font-mono text-sm">{a.metric}</p><p className="text-xs text-white/50">{a.type} | Baseline: {a.baseline} → Current: {a.current} | {a.sigma}σ</p></div><StatusBadge status={a.sev} /></div>))}</div>)}
    {tab === "baselines" && (<div className="card-surface p-6"><h3 className="section-heading">Baseline Health</h3><div className="grid grid-cols-2 gap-4">
      {[{ m: "Metrics with stable baselines", v: "1,182 (95%)" }, { m: "Baselines recalculated (24h)", v: "89" }, { m: "Seasonal patterns detected", v: "34" }, { m: "Avg baseline age", v: "7.2 days" }].map((s) => (
        <div key={s.m} className="card-interactive p-4"><p className="text-sm text-white/60">{s.m}</p><p className="text-2xl font-bold text-white mt-1">{s.v}</p></div>))}</div></div>)}
    {tab === "alerts" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Alerts</h3>
      {[{ metric: "api-gateway.p99_latency", action: "PagerDuty page sent", when: "12 min ago" },
        { metric: "billing.error_rate", action: "Slack notification sent", when: "45 min ago" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.metric}</p><p className="text-xs text-white/50">{a.action}</p></div><span className="text-xs text-white/40">{a.when}</span></div>))}</div>)}
  </div>);
}
