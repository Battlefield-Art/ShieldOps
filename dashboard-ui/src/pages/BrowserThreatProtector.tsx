import { useState } from "react";
import { Globe, Shield, AlertTriangle, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "threats" | "isolation_sessions" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "threats", label: "Threats" },
  { id: "isolation_sessions", label: "Isolation Sessions" },
  { id: "metrics", label: "Metrics" },
];

const THREATS = [
  { url: "login-secure.evil-corp.xyz/auth", category: "Phishing", reputation: "Malicious", risk: "critical", detail: "Credential harvesting page mimicking corporate SSO" },
  { url: "cdn-fast.download.ru/update.exe", category: "Malware", reputation: "Malicious", risk: "critical", detail: "Drive-by download of trojanized executable" },
  { url: "analytics-track.io/mine.js", category: "Cryptominer", reputation: "Suspicious", risk: "high", detail: "Coinhive-based cryptominer JavaScript detected" },
  { url: "docs-share.biz/invoice.html", category: "Phishing", reputation: "Suspicious", risk: "high", detail: "Fake invoice page with obfuscated form submission" },
  { url: "news-update.info/article?ref=42", category: "Drive-by", reputation: "Suspicious", risk: "medium", detail: "Exploit kit landing page with browser fingerprinting" },
];

export default function BrowserThreatProtector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Browser Threat Protector" subtitle="Browser-based threat isolation and protection" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="URLs Analyzed" value="12,847" icon={<Globe className="h-5 w-5" />} />
        <MetricCard title="Threats Blocked" value="89" icon={<Shield className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Sessions Isolated" value="234" icon={<Lock className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Malicious JS" value="17" icon={<AlertTriangle className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Phishing", v: "42", c: "text-red-400" }, { l: "Malware", v: "23", c: "text-orange-400" }, { l: "Cryptominer", v: "12", c: "text-yellow-400" }, { l: "Drive-by", v: "12", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "threats" && (<div className="space-y-3">{THREATS.map((t, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{t.url}</span><span className="ml-2 text-xs text-white/40">{t.category}</span></div><StatusBadge status={t.risk} /></div><p className="text-white/50 text-sm">{t.detail}</p><span className="text-xs text-white/40">Reputation: {t.reputation}</span></div>))}</div>)}
      {tab === "isolation_sessions" && (<div className="card-surface p-6"><h3 className="section-heading">Active Isolation Sessions</h3><div className="space-y-2">{[{ url: "suspicious-site.xyz/page", container: "iso-a3f2b1", status: "active", streams: true }, { url: "download-free.ru/app", container: "iso-c7d4e9", status: "active", streams: true }, { url: "login-verify.biz/auth", container: "iso-f1a8c3", status: "scanning", streams: true }, { url: "news-update.info/article", container: "iso-b2e5d7", status: "completed", streams: false }].map((s, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70 font-mono">{s.url}</span><span className="ml-2 text-xs text-white/40">{s.container}</span></div><div className="flex gap-3"><span className={clsx("text-xs", s.status === "active" ? "text-emerald-400" : s.status === "scanning" ? "text-yellow-400" : "text-white/40")}>{s.status}</span>{s.streams && <span className="text-xs text-cyan-400">pixel-streaming</span>}</div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Protection Metrics</h3>{[{ m: "Block Rate", v: "99.2%", t: "+0.3% vs last week" }, { m: "Avg Isolation Time", v: "45ms", t: "-12ms" }, { m: "False Positive Rate", v: "1.8%", t: "-0.2%" }, { m: "Content Scan Speed", v: "2.1s avg", t: "-0.3s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
