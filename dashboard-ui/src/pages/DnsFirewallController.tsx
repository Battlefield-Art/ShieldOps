import { useState } from "react";
import { Shield, Globe, AlertTriangle, Activity, Filter } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "blocked_domains" | "tunneling" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "blocked_domains", label: "Blocked Domains" },
  { id: "tunneling", label: "Tunneling Detection" },
  { id: "metrics", label: "Metrics" },
];

const BLOCKED = [
  { domain: "evil-payload.xyz", category: "Malware C2", queries: 342, status: "critical" },
  { domain: "phish-login.net", category: "Phishing", queries: 128, status: "high" },
  { domain: "crypto-mine.io", category: "Cryptomining", queries: 89, status: "medium" },
  { domain: "data-exfil.ru", category: "Data Exfil", queries: 56, status: "critical" },
  { domain: "ad-track.biz", category: "Adware", queries: 1204, status: "low" },
];

export default function DnsFirewallController() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="DNS Firewall Controller" subtitle="DNS-layer security and content filtering" icon={<Shield className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Queries/min" value="12,847" icon={<Globe className="h-5 w-5" />} />
        <MetricCard title="Blocked" value="1,819" icon={<Filter className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Tunneling Alerts" value="7" icon={<AlertTriangle className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="DGA Detected" value="23" icon={<Activity className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Query Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Allowed", v: "11,028", c: "text-emerald-400" }, { l: "Blocked", v: "1,819", c: "text-red-400" }, { l: "Sinkholed", v: "342", c: "text-orange-400" }, { l: "Tunneling", v: "7", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "blocked_domains" && (<div className="space-y-3">{BLOCKED.map((d) => (<div key={d.domain} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{d.domain}</span><span className="ml-2 text-xs text-white/40">{d.category}</span></div><StatusBadge status={d.status} /></div><span className="text-xs text-white/40">{d.queries} queries blocked</span></div>))}</div>)}
      {tab === "tunneling" && (<div className="card-surface p-6"><h3 className="section-heading">DNS Tunneling Detection</h3><div className="space-y-2">{[{ src: "10.0.4.18", domain: "t1.evil.xyz", entropy: 4.2, confidence: "high" }, { src: "10.0.8.33", domain: "d2.c2tunnel.net", entropy: 3.8, confidence: "high" }, { src: "10.0.1.5", domain: "sub.legit.com", entropy: 2.1, confidence: "low" }].map((t, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70 font-mono">{t.src}</span><span className="text-white/40 mx-2">→</span><span className="text-white/70 font-mono">{t.domain}</span></div><div className="flex gap-3"><span className="text-white/40">entropy: {t.entropy}</span><StatusBadge status={t.confidence} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">DNS Security Trends</h3>{[{ m: "Block Rate", v: "14.2%", t: "+1.3% vs last week" }, { m: "DGA Domains", v: "23", t: "+5 new today" }, { m: "Tunneling Incidents", v: "7", t: "-2 vs yesterday" }, { m: "Avg Response Time", v: "1.2ms", t: "within SLA" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
