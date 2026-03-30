import { useState } from "react";
import { FileText, AlertTriangle, Activity, Layers, BarChart3, Search } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "anomalies" | "correlations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "anomalies", label: "Anomalies" },
  { id: "correlations", label: "Correlations" },
  { id: "metrics", label: "Metrics" },
];

const ANOMALIES = [
  { pattern: "auth.login_failure spike", source: "security", type: "Frequency Spike", severity: "critical", confidence: "97%" },
  { pattern: "db.query_timeout new pattern", source: "application", type: "New Pattern", severity: "high", confidence: "89%" },
  { pattern: "cron.backup missing event", source: "syslog", type: "Missing Event", severity: "high", confidence: "92%" },
  { pattern: "api.rate_limit volume anomaly", source: "application", type: "Volume Anomaly", severity: "medium", confidence: "78%" },
  { pattern: "k8s.pod_restart sequence break", source: "container", type: "Sequence Break", severity: "medium", confidence: "74%" },
];

export default function LogAnomalyDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Log Anomaly Detector" subtitle="ML-based log anomaly detection and correlation" icon={<Search className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Records Analyzed" value="2.4M" icon={<FileText className="h-5 w-5" />} />
        <MetricCard title="Anomalies Detected" value="47" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Correlations" value="12" icon={<Layers className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Active Alerts" value="8" icon={<Activity className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Source Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Application", v: "1.1M", c: "text-cyan-400" }, { l: "Security", v: "680K", c: "text-red-400" }, { l: "Syslog", v: "420K", c: "text-yellow-400" }, { l: "Container", v: "200K", c: "text-blue-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.pattern} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{a.pattern}</span><span className="ml-2 text-xs text-white/40">{a.type}</span></div><StatusBadge status={a.severity} /></div><div className="flex justify-between text-sm"><span className="text-white/50">Source: {a.source}</span><span className="text-cyan-400 font-mono">{a.confidence} confidence</span></div></div>))}</div>)}
      {tab === "correlations" && (<div className="card-surface p-6"><h3 className="section-heading">Cross-Source Correlations</h3><div className="space-y-2">{[{ desc: "Auth failures + DB timeouts + API rate spikes", sources: 3, score: "0.94", severity: "critical" }, { desc: "Pod restarts + missing backup events", sources: 2, score: "0.82", severity: "high" }, { desc: "New login pattern + security log gaps", sources: 2, score: "0.71", severity: "medium" }].map((c, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div className="flex-1"><span className="text-white/70">{c.desc}</span><span className="ml-2 text-xs text-white/40">{c.sources} sources</span></div><div className="flex gap-3"><span className="text-cyan-400 font-mono">{c.score}</span><StatusBadge status={c.severity} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detection Trends</h3>{[{ m: "Daily Log Volume", v: "2.4M records", t: "+180K vs yesterday" }, { m: "New Patterns/Day", v: "14", t: "-3" }, { m: "False Positive Rate", v: "4.2%", t: "-1.1%" }, { m: "Mean Detection Time", v: "38s", t: "-12s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
