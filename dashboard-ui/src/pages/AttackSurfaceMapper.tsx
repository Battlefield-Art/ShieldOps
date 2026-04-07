import { useState } from "react";
import { Globe, AlertTriangle, Eye, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "assets" | "attack_paths" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "assets", label: "Exposed Assets" },
  { id: "attack_paths", label: "Attack Paths" },
  { id: "metrics", label: "Metrics" },
];

const ASSETS = [
  { name: "api.shieldops.io", type: "API", exposure: "Internet", risk: "high", detail: "12 endpoints, 3 without rate limiting" },
  { name: "admin.internal.co", type: "Web App", exposure: "DMZ", risk: "critical", detail: "Admin panel accessible from DMZ, weak auth" },
  { name: "s3://prod-backups", type: "Storage", exposure: "Internet", risk: "high", detail: "Bucket policy allows public ListBucket" },
  { name: "10.0.4.22:5432", type: "Database", exposure: "Internal", risk: "medium", detail: "PostgreSQL on default port, no network policy" },
  { name: "*.staging.co", type: "DNS", exposure: "Internet", risk: "medium", detail: "Wildcard DNS — subdomain takeover risk" },
];

export default function AttackSurfaceMapper() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Attack Surface Mapper" subtitle="Continuous attack surface discovery and risk mapping" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Assets Discovered" value="847" icon={<Eye className="h-5 w-5" />} />
        <MetricCard title="Internet Exposed" value="124" icon={<Globe className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Attack Paths" value="23" icon={<Target className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Shadow IT" value="12" icon={<AlertTriangle className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Exposure Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Internet", v: "124", c: "text-red-400" }, { l: "DMZ", v: "45", c: "text-orange-400" }, { l: "Internal", v: "590", c: "text-yellow-400" }, { l: "Restricted", v: "88", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "assets" && (<div className="space-y-3">{ASSETS.map((a) => (<div key={a.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{a.name}</span><span className="ml-2 text-xs text-white/40">{a.type}</span></div><StatusBadge status={a.risk} /></div><p className="text-white/50 text-sm">{a.detail}</p><span className="text-xs text-white/40">Exposure: {a.exposure}</span></div>))}</div>)}
      {tab === "attack_paths" && (<div className="card-surface p-6"><h3 className="section-heading">Critical Attack Paths</h3><div className="space-y-2">{[{ path: "Phishing → VPN → Lateral Move → DB", steps: 4, risk: "critical" }, { path: "Public API → SSRF → Internal Service → S3", steps: 4, risk: "high" }, { path: "Shadow IT → Unpatched → Privilege Esc", steps: 3, risk: "high" }].map((p, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70">{p.path}</span><div className="flex gap-3"><span className="text-white/40">{p.steps} steps</span><StatusBadge status={p.risk} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Surface Trends</h3>{[{ m: "Total Surface Area", v: "847 assets", t: "+12 this week" }, { m: "Reduction Rate", v: "23%", t: "+5% vs last month" }, { m: "Shadow IT Detected", v: "12", t: "-3" }, { m: "Avg Risk Score", v: "6.2/10", t: "-0.4" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
