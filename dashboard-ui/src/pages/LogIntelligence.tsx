import { useState } from "react";
import { FileText, Activity, AlertTriangle, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "patterns" | "threats" | "sources";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "patterns", label: "Patterns" }, { id: "threats", label: "Threats" }, { id: "sources", label: "Sources" }];
export default function LogIntelligence() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Log Intelligence" subtitle="AI-native log analytics across any source — Splunk, Elastic, CloudWatch, Datadog" icon={<FileText className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Logs Ingested (24h)" value="847M" icon={<FileText className="h-5 w-5" />} />
      <MetricCard title="Patterns Detected" value="234" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Threat Correlations" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Query Performance" value="0.8s" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Log Analytics vs LogScale</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Sources Supported", ours: "Any (17+)", theirs: "LogScale only", color: "text-cyan-400" },
        { label: "Analysis Method", ours: "LLM + Statistical", theirs: "Indexed Search", color: "text-emerald-400" },
        { label: "Avg Query Time", ours: "0.8s", theirs: "~2s", color: "text-cyan-400" }].map((c) => (
        <div key={c.label} className="card-interactive p-4"><p className="text-sm text-white/60">{c.label}</p><div className="flex justify-between mt-2"><div><p className="text-white/40 text-xs">ShieldOps</p><p className={clsx("font-bold", c.color)}>{c.ours}</p></div><div className="text-right"><p className="text-white/40 text-xs">LogScale</p><p className="text-white/30">{c.theirs}</p></div></div></div>))}</div></div>)}
    {tab === "patterns" && (<div className="space-y-3">
      {[{ id: "PAT-234", type: "Security Event", pattern: "Failed auth spike from 3 IPs", freq: "12x baseline", severity: "high" },
        { id: "PAT-233", type: "Anomaly", pattern: "Unusual API call sequence at 3am", freq: "First seen", severity: "medium" },
        { id: "PAT-232", type: "Error Spike", pattern: "500 errors on /api/v1/auth", freq: "5x baseline", severity: "medium" },
      ].map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="text-xs text-white/40 ml-2">{p.type}</span></div><StatusBadge status={p.severity} /></div>
        <p className="text-white/90 font-medium">{p.pattern}</p><p className="text-xs text-white/50">Frequency: {p.freq}</p></div>))}</div>)}
    {tab === "threats" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Correlated Threats</h3>
      {[{ threat: "Brute force → credential compromise → data access", sources: "Splunk + Okta + CloudWatch", confidence: 0.92, mitre: "T1110 → T1078 → T1530" },
        { threat: "API abuse pattern correlating with known botnet", sources: "Elastic + Datadog", confidence: 0.87, mitre: "T1190" },
      ].map((t, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{t.threat}</p><p className="text-xs text-white/50">Sources: {t.sources} | MITRE: {t.mitre}</p><p className="text-xs text-cyan-400">Confidence: {t.confidence}</p></div>))}</div>)}
    {tab === "sources" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Volume (24h)</th><th className="px-4 py-3">Patterns</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { src: "Splunk", vol: "312M", patterns: 89, status: "connected" },
        { src: "Elastic", vol: "245M", patterns: 67, status: "connected" },
        { src: "CloudWatch", vol: "178M", patterns: 45, status: "connected" },
        { src: "Datadog", vol: "112M", patterns: 33, status: "connected" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{s.src}</td><td className="px-4 py-3 text-white/80">{s.vol}</td><td className="px-4 py-3 text-white/70">{s.patterns}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
  </div>);
}
