import { useState } from "react";
import { Cloud, Shield, AlertTriangle, BarChart3, Lock, Layers } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "posture" | "threats" | "response";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "posture", label: "Posture" }, { id: "threats", label: "Threats" }, { id: "response", label: "Response" }];
export default function UnifiedCloudSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Unified Cloud Security" subtitle="Multi-cloud CSPM + CWPP + CDR + CIEM + DSPM — no vendor lock-in" icon={<Cloud className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Cloud Accounts" value="12" icon={<Cloud className="h-5 w-5" />} />
      <MetricCard title="Security Score" value="87%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Active Threats" value="5" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Functions" value="5/5" icon={<Layers className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Security Functions</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-3">
      {[{ fn: "CSPM", score: 89, color: "text-emerald-400" }, { fn: "CWPP", score: 91, color: "text-emerald-400" }, { fn: "CDR", score: 85, color: "text-cyan-400" }, { fn: "CIEM", score: 78, color: "text-yellow-400" }, { fn: "DSPM", score: 82, color: "text-cyan-400" }].map((f) => (
        <div key={f.fn} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{f.fn}</p><p className={clsx("text-2xl font-bold mt-1", f.color)}>{f.score}%</p></div>))}</div></div>)}
    {tab === "posture" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Provider</th><th className="px-4 py-3">Accounts</th><th className="px-4 py-3">Score</th><th className="px-4 py-3">Critical</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { provider: "AWS", accounts: 5, score: 88, critical: 3, status: "monitored" },
        { provider: "GCP", accounts: 3, score: 91, critical: 1, status: "monitored" },
        { provider: "Azure", accounts: 2, score: 84, critical: 2, status: "monitored" },
        { provider: "Kubernetes", accounts: 2, score: 86, critical: 1, status: "monitored" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{p.provider}</td><td className="px-4 py-3 text-white/80">{p.accounts}</td><td className="px-4 py-3 text-emerald-400">{p.score}%</td><td className="px-4 py-3 text-red-400">{p.critical}</td><td className="px-4 py-3"><StatusBadge status={p.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "threats" && (<div className="space-y-3">
      {[{ id: "CST-005", threat: "S3 bucket public with customer data", provider: "AWS", function: "DSPM", severity: "critical" },
        { id: "CST-004", threat: "Over-privileged service account", provider: "GCP", function: "CIEM", severity: "high" },
        { id: "CST-003", threat: "Container escape attempt", provider: "K8s", function: "CWPP", severity: "critical" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.provider} | {t.function}</span></div><StatusBadge status={t.severity} /></div>
        <p className="text-white/90 font-medium">{t.threat}</p></div>))}</div>)}
    {tab === "response" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Automated Responses</h3>
      {[{ action: "Restricted S3 bucket ACL", threat: "CST-005", provider: "AWS", time: "0.3s", status: "completed" },
        { action: "Reduced SA permissions", threat: "CST-004", provider: "GCP", time: "0.8s", status: "completed" },
        { action: "Killed container + isolated pod", threat: "CST-003", provider: "K8s", time: "0.5s", status: "completed" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.provider} | {r.threat} | {r.time}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
