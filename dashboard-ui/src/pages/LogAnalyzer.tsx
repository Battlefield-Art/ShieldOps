import { useState } from "react";
import { FileText, AlertTriangle, Search, Activity, Link2, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "anomalies" | "patterns" | "correlations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "anomalies", label: "Anomalies" }, { id: "patterns", label: "Patterns" }, { id: "correlations", label: "Correlations" }];
export default function LogAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Log Analyzer" subtitle="Log anomaly detection with pattern matching and statistical analysis" icon={<FileText className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Logs Analyzed (24h)" value="4.2M" icon={<FileText className="h-5 w-5" />} />
      <MetricCard title="Anomalies Detected" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Patterns Tracked" value="847" icon={<Search className="h-5 w-5" />} />
      <MetricCard title="Correlations" value="5" icon={<Link2 className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Log Source Distribution</h3>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {[{ src: "Application", count: "1.8M", anomalies: 5 }, { src: "System", count: "980K", anomalies: 2 }, { src: "Security", count: "420K", anomalies: 3 }, { src: "Network", count: "640K", anomalies: 1 }, { src: "K8s", count: "360K", anomalies: 1 }].map((s) => (
          <div key={s.src} className="card-interactive p-3 text-center"><p className="text-xs text-white/50">{s.src}</p><p className="text-xl font-bold text-white">{s.count}</p><p className="text-xs text-red-400">{s.anomalies} anomalies</p></div>))}
      </div></div>)}
    {tab === "anomalies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Anomalies</h3>
      {[{ type: "Error Spike", src: "Application", desc: "NullPointerException rate 5x baseline in user-service", sev: "critical", deviation: "+420%" },
        { type: "New Pattern", src: "Security", desc: "Previously unseen auth failure pattern from internal IPs", sev: "high", deviation: "New" },
        { type: "Volume Drop", src: "K8s", desc: "scheduler logs dropped 90% — possible component failure", sev: "high", deviation: "-90%" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.type} ({a.src})</p><p className="text-xs text-white/50">{a.desc}</p></div><div className="text-right"><StatusBadge status={a.sev} /><p className="text-xs text-red-400 mt-1">{a.deviation}</p></div></div>))}</div>)}
    {tab === "patterns" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Top Patterns (24h)</h3>
      <div className="grid grid-cols-2 gap-4">
        {[{ pattern: "Connection timeout", count: 12400, trend: "+180%" }, { pattern: "Authentication failure", count: 8900, trend: "+45%" }, { pattern: "Rate limit exceeded", count: 3200, trend: "-12%" }, { pattern: "Out of memory", count: 890, trend: "+320%" }].map((p) => (
          <div key={p.pattern} className="card-interactive p-4"><p className="text-white/90 font-medium">{p.pattern}</p><p className="text-xs text-white/50">{p.count.toLocaleString()} occurrences | Trend: <span className={p.trend.startsWith("+") ? "text-red-400" : "text-emerald-400"}>{p.trend}</span></p></div>))}
      </div></div>)}
    {tab === "correlations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Event Correlations</h3>
      {[{ events: ["NullPointerException spike", "Memory pressure in user-service", "Recent deployment v2.4.1"], hypothesis: "Deployment v2.4.1 introduced memory leak causing NPEs", conf: 89 },
        { events: ["Auth failure spike", "New IP range in access logs"], hypothesis: "Credential stuffing attack from new botnet", conf: 82 },
      ].map((c, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{c.hypothesis}</p><p className="text-xs text-white/50 mt-1">Events: {c.events.join(" + ")}</p><p className="text-xs text-cyan-400 mt-1">Confidence: {c.conf}%</p></div>))}</div>)}
  </div>);
}
