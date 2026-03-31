import { useState } from "react";
import { Target, Eye, AlertTriangle, Activity, Users, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "decoy_network" | "attacker_activity" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "decoy_network", label: "Decoy Network" },
  { id: "attacker_activity", label: "Attacker Activity" },
  { id: "metrics", label: "Metrics" },
];

const DECOYS = [
  { name: "honey-db-01", type: "Database", subnet: "10.0.5.0/24", interactions: 12, status: "active" },
  { name: "honey-web-03", type: "Web Server", subnet: "10.0.2.0/24", interactions: 34, status: "triggered" },
  { name: "honey-ssh-02", type: "SSH Server", subnet: "10.0.8.0/24", interactions: 8, status: "active" },
  { name: "honey-file-01", type: "File Share", subnet: "10.0.3.0/24", interactions: 0, status: "idle" },
  { name: "honey-api-01", type: "API Endpoint", subnet: "10.0.1.0/24", interactions: 5, status: "active" },
];

export default function DeceptionNetworkManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Deception Network Manager" subtitle="Honeypot and deception technology management" icon={<Target className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Decoys" value="24" icon={<Target className="h-5 w-5" />} />
        <MetricCard title="Interactions" value="59" icon={<Eye className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Attackers Profiled" value="7" icon={<Users className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Intel Generated" value="18" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Decoy Status</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Active", v: "18", c: "text-emerald-400" }, { l: "Triggered", v: "3", c: "text-red-400" }, { l: "Idle", v: "3", c: "text-white/40" }, { l: "Deploying", v: "0", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "decoy_network" && (<div className="space-y-3">{DECOYS.map((d) => (<div key={d.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{d.name}</span><span className="ml-2 text-xs text-white/40">{d.type}</span></div><StatusBadge status={d.status === "triggered" ? "critical" : d.status === "active" ? "healthy" : "low"} /></div><div className="flex gap-4 text-xs text-white/40"><span>Subnet: {d.subnet}</span><span>{d.interactions} interactions</span></div></div>))}</div>)}
      {tab === "attacker_activity" && (<div className="card-surface p-6"><h3 className="section-heading">Recent Attacker Profiles</h3><div className="space-y-2">{[{ ip: "203.0.113.42", ttps: "T1078, T1021", sessions: 8, confidence: "high" }, { ip: "198.51.100.17", ttps: "T1110, T1059", sessions: 3, confidence: "medium" }, { ip: "192.0.2.88", ttps: "T1083, T1057", sessions: 12, confidence: "high" }].map((a, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70 font-mono">{a.ip}</span><span className="text-white/40 ml-2">TTPs: {a.ttps}</span></div><div className="flex gap-3"><span className="text-white/40">{a.sessions} sessions</span><StatusBadge status={a.confidence} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Deception Metrics</h3>{[{ m: "Detection Rate", v: "94%", t: "of intrusions detected via decoys" }, { m: "Avg Dwell Time", v: "4.2 min", t: "attacker engagement duration" }, { m: "Intel Quality", v: "8.1/10", t: "+0.3 vs last month" }, { m: "False Positive Rate", v: "2.1%", t: "-0.5% improved" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
