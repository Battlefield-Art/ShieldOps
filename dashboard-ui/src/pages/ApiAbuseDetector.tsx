import { useState } from "react";
import { ShieldAlert, Activity, Ban, AlertTriangle, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "abuse_patterns" | "mitigations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "abuse_patterns", label: "Abuse Patterns" },
  { id: "mitigations", label: "Mitigations" },
  { id: "metrics", label: "Metrics" },
];

const PATTERNS = [
  { endpoint: "/api/v1/auth/login", type: "Credential Stuffing", source: "23 rotating IPs", risk: "critical", detail: "4,200 failed logins in 15min, distributed across residential proxies" },
  { endpoint: "/api/v1/users", type: "Scraping", source: "bot-net cluster", risk: "high", detail: "Sequential enumeration of user profiles, 800 req/min" },
  { endpoint: "/api/v1/search", type: "Rate Limit Evasion", source: "12 IPs", risk: "high", detail: "Slow-and-low scraping at 58 req/min per IP, rotating user agents" },
  { endpoint: "/api/v1/payments", type: "Enumeration", source: "single IP", risk: "medium", detail: "Card number enumeration via BIN testing, 120 attempts" },
  { endpoint: "/api/v1/graphql", type: "Data Exfiltration", source: "internal IP", risk: "medium", detail: "Deep nested queries extracting bulk PII data" },
];

export default function ApiAbuseDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="API Abuse Detector" subtitle="Real-time API abuse detection and automated mitigation" icon={<ShieldAlert className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Requests" value="2.4M" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Abuse Patterns" value="18" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Sources Blocked" value="47" icon={<Ban className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Mitigations Active" value="12" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Credential Stuffing", v: "6", c: "text-red-400" }, { l: "Rate Evasion", v: "5", c: "text-orange-400" }, { l: "Scraping", v: "4", c: "text-yellow-400" }, { l: "Bot Traffic", v: "3", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "abuse_patterns" && (<div className="space-y-3">{PATTERNS.map((p) => (<div key={p.endpoint} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{p.endpoint}</span><span className="ml-2 text-xs text-white/40">{p.type}</span></div><StatusBadge status={p.risk} /></div><p className="text-white/50 text-sm">{p.detail}</p><span className="text-xs text-white/40">Source: {p.source}</span></div>))}</div>)}
      {tab === "mitigations" && (<div className="card-surface p-6"><h3 className="section-heading">Active Mitigations</h3><div className="space-y-2">{[{ action: "Block 23 rotating proxy IPs on /auth/login", type: "IP Block", status: "active" }, { action: "Rate limit /api/v1/users to 10 req/min per IP", type: "Rate Limit", status: "active" }, { action: "CAPTCHA challenge on /api/v1/search after 30 req/min", type: "Challenge", status: "active" }, { action: "WAF rule: block sequential card BIN enumeration", type: "WAF Rule", status: "pending" }].map((m, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70">{m.action}</span><div className="flex gap-3"><span className="text-white/40">{m.type}</span><StatusBadge status={m.status === "active" ? "low" : "medium"} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detection Metrics</h3>{[{ m: "Detection Rate", v: "94.2%", t: "+2.1% vs last week" }, { m: "False Positive Rate", v: "3.8%", t: "-0.5%" }, { m: "Avg Response Time", v: "1.2s", t: "-0.3s" }, { m: "Blocked Requests", v: "142K", t: "+18K this week" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
