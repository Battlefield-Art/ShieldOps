import { useState } from "react";
import { Radio, AlertTriangle, Activity, Layers, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "signal_feed" | "correlations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "signal_feed", label: "Signal Feed" },
  { id: "correlations", label: "Correlations" },
  { id: "metrics", label: "Metrics" },
];

const CORRELATIONS = [
  { id: "COR-001", pattern: "Multi-stage attack on workstation-42", strength: "strong", signals: 3, detail: "PowerShell execution + lateral movement + DNS exfil from same host" },
  { id: "COR-002", pattern: "Cross-entity privilege escalation campaign", strength: "moderate", signals: 2, detail: "Service account privilege escalation + IAM role creation" },
  { id: "COR-003", pattern: "API abuse with data access", strength: "moderate", signals: 2, detail: "Unusual API volume correlated with bulk S3 download" },
  { id: "COR-004", pattern: "Brute-force with credential abuse", strength: "strong", signals: 4, detail: "12 auth failures followed by successful login and data exfil" },
];

export default function SecuritySignalCorrelator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Signal Correlator" subtitle="Cross-domain security signal correlation and incident generation" icon={<Radio className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Signals Collected" value="2,847" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Correlations Found" value="34" icon={<Layers className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Incidents Generated" value="8" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Noise Reduced" value="94%" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Signal Sources</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "EDR", v: "892", c: "text-cyan-400" }, { l: "SIEM", v: "1,204", c: "text-emerald-400" }, { l: "Cloud", v: "534", c: "text-yellow-400" }, { l: "Identity", v: "217", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "signal_feed" && (<div className="card-surface p-6"><p className="text-white/60">Real-time security signal feed from 6 sources with MITRE ATT&CK mapping and entity resolution.</p></div>)}
      {tab === "correlations" && (<div className="space-y-3">{CORRELATIONS.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-white/90 font-medium">{c.pattern}</span></div><StatusBadge status={c.strength} /></div><p className="text-white/70 text-sm">{c.signals} signals correlated</p><p className="text-white/50 text-xs mt-1">{c.detail}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Correlation Performance</h3>{[{ m: "Correlation Accuracy", v: "96.2%", t: "+1.4%" }, { m: "False Positive Rate", v: "2.1%", t: "-0.8%" }, { m: "Avg Correlation Time", v: "340ms", t: "-60ms" }, { m: "MITRE Coverage", v: "78%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
