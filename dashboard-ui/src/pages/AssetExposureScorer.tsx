import { useState } from "react";
import { Globe, Shield, AlertTriangle, Eye, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "exposed_assets" | "exposure_scores" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "exposed_assets", label: "Exposed Assets" },
  { id: "exposure_scores", label: "Exposure Scores" },
  { id: "metrics", label: "Metrics" },
];

const ASSETS = [
  { id: "DA-001", hostname: "api.acme-corp.com", type: "API Endpoint", score: 8.2, severity: "critical", detail: "CVE-2024-21762 (RCE), CVE-2024-3400 (Auth Bypass), HTTPS/443" },
  { id: "DA-002", hostname: "db-replica.acme-corp.com", type: "Database", score: 7.5, severity: "high", detail: "PostgreSQL 15.4 on port 5432 exposed, 1 CVE, risky port" },
  { id: "DA-003", hostname: "mail.acme-corp.com", type: "Mail Server", score: 6.3, severity: "high", detail: "Postfix 3.8.4, SMTP/25 exposed, no TLS enforcement" },
  { id: "DA-004", hostname: "dashboard.acme-corp.com", type: "Web App", score: 4.1, severity: "medium", detail: "Apache 2.4.58, HTTPS/443, 1 medium CVE" },
  { id: "DA-005", hostname: "cdn.acme-corp.com", type: "Load Balancer", score: 2.0, severity: "low", detail: "HAProxy 2.9.1, HTTPS/443, clean" },
];

export default function AssetExposureScorer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Asset Exposure Scorer" subtitle="Internet-facing asset exposure scoring and trending" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Assets Discovered" value="247" icon={<Eye className="h-5 w-5" />} />
        <MetricCard title="Critical Exposures" value="14" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Avg Exposure Score" value="4.8" icon={<Target className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Score Improvements" value="23" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Exposure Distribution</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-4">{[{ l: "Critical", v: "14", c: "text-red-400" }, { l: "High", v: "38", c: "text-orange-400" }, { l: "Medium", v: "72", c: "text-yellow-400" }, { l: "Low", v: "91", c: "text-blue-400" }, { l: "Minimal", v: "32", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "exposed_assets" && (<div className="space-y-3">{ASSETS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-white/90 font-medium">{a.hostname}</span></div><StatusBadge status={a.severity} /></div><p className="text-white/70 text-sm">{a.type} | Score: {a.score}/10</p><p className="text-white/50 text-xs mt-1">{a.detail}</p></div>))}</div>)}
      {tab === "exposure_scores" && (<div className="card-surface p-6"><h3 className="section-heading">Score Breakdown</h3><div className="space-y-3">{ASSETS.map((a) => (<div key={a.id} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.hostname}</p><p className="text-xs text-white/50">{a.type}</p></div><div className="text-right"><span className={clsx("font-mono font-bold", a.score >= 7 ? "text-red-400" : a.score >= 4 ? "text-yellow-400" : "text-emerald-400")}>{a.score}/10</span></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Exposure Trends</h3>{[{ m: "Assets Scanned (30d)", v: "247", t: "+18" }, { m: "Avg Score Delta", v: "-0.4", t: "Improving" }, { m: "New CVEs Detected", v: "7", t: "+3 this week" }, { m: "Remediation Rate", v: "72%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
