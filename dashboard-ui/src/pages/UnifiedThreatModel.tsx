import { useState } from "react";
import { Target, Shield, AlertTriangle, Eye, Crosshair, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "threat_catalog" | "risk_matrix" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "threat_catalog", label: "Threat Catalog" },
  { id: "risk_matrix", label: "Risk Matrix" },
  { id: "metrics", label: "Metrics" },
];

const THREATS = [
  { title: "SQL Injection via API Gateway", category: "Tampering", asset: "payment-api", risk: "critical", detail: "DREAD 8.4 -- unvalidated input in /charges endpoint" },
  { title: "Privilege Escalation in Auth Service", category: "Elevation of Privilege", asset: "auth-gateway", risk: "critical", detail: "DREAD 7.9 -- role bypass via token manipulation" },
  { title: "Data Exfiltration via S3 Bucket", category: "Information Disclosure", asset: "s3://prod-data", risk: "high", detail: "DREAD 7.2 -- overly permissive bucket policy" },
  { title: "DoS on Public API", category: "Denial of Service", asset: "api.shieldops.io", risk: "high", detail: "DREAD 6.8 -- no rate limiting on search endpoint" },
  { title: "Session Replay Attack", category: "Spoofing", asset: "web-frontend", risk: "medium", detail: "DREAD 5.1 -- weak session token rotation" },
];

export default function UnifiedThreatModel() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Unified Threat Model" subtitle="STRIDE/DREAD threat modeling, risk calculation, and mitigation prioritization" icon={<Target className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Assets in Scope" value="234" icon={<Eye className="h-5 w-5" />} />
        <MetricCard title="Threats Identified" value="89" icon={<Target className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Control Gaps" value="17" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Mitigations" value="42" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">STRIDE Distribution</h3><div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">{[{ l: "Spoofing", v: "12", c: "text-orange-400" }, { l: "Tampering", v: "18", c: "text-red-400" }, { l: "Repudiation", v: "8", c: "text-yellow-400" }, { l: "Info Disclosure", v: "22", c: "text-red-400" }, { l: "DoS", v: "15", c: "text-orange-400" }, { l: "Priv Escalation", v: "14", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-xs text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "threat_catalog" && (<div className="space-y-3">{THREATS.map((t) => (<div key={t.title} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium text-sm">{t.title}</span><span className="ml-2 text-xs text-white/40">{t.category}</span></div><StatusBadge status={t.risk} /></div><p className="text-white/50 text-sm">{t.detail}</p><span className="text-xs text-white/40">Asset: {t.asset}</span></div>))}</div>)}
      {tab === "risk_matrix" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Heat Map</h3><div className="space-y-2">{[{ level: "Critical", count: 8, pct: "9%", color: "text-red-400" }, { level: "High", count: 24, pct: "27%", color: "text-orange-400" }, { level: "Medium", count: 38, pct: "43%", color: "text-yellow-400" }, { level: "Low", count: 15, pct: "17%", color: "text-emerald-400" }, { level: "Negligible", count: 4, pct: "4%", color: "text-white/40" }].map((r) => (<div key={r.level} className="card-interactive p-3 flex items-center justify-between text-sm"><span className={clsx("font-medium", r.color)}>{r.level}</span><div className="flex gap-4"><span className="text-white/50">{r.count} threats</span><span className="text-white/40">{r.pct}</span></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Threat Model Trends</h3>{[{ m: "Model Coverage", v: "87%", t: "+5% this quarter" }, { m: "Avg DREAD Score", v: "5.8", t: "-0.3 vs last model" }, { m: "Control Effectiveness", v: "72%", t: "+8%" }, { m: "Mitigation Completion", v: "64%", t: "+12%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
