import { useState } from "react";
import { Lock, Globe, AlertTriangle, Search, Eye, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "certificate_feed" | "anomalies" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "certificate_feed", label: "Certificate Feed" },
  { id: "anomalies", label: "Anomalies" },
  { id: "metrics", label: "Metrics" },
];

const CERTS = [
  { id: "CT-001", domain: "shieldops.io", issuer: "Let's Encrypt", san: 3, status: "valid", days: 87 },
  { id: "CT-002", domain: "sh1eldops.io", issuer: "ZeroSSL", san: 1, status: "suspicious", days: 14 },
  { id: "CT-003", domain: "shieldops-login.com", issuer: "Sectigo", san: 2, status: "suspicious", days: 7 },
  { id: "CT-004", domain: "api.shieldops.io", issuer: "DigiCert", san: 1, status: "valid", days: 365 },
  { id: "CT-005", domain: "shie1dops.net", issuer: "Unknown CA", san: 1, status: "malicious", days: 3 },
];

const ANOMALIES = [
  { id: "AN-001", domain: "sh1eldops.io", type: "Homoglyph Impersonation", severity: "high", confidence: 0.94 },
  { id: "AN-002", domain: "shieldops-login.com", type: "Combosquatting", severity: "critical", confidence: 0.97 },
  { id: "AN-003", domain: "shie1dops.net", type: "Typosquatting", severity: "critical", confidence: 0.99 },
];

export default function CertificateTransparencyMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Certificate Transparency Monitor" subtitle="CT log monitoring and domain impersonation detection" icon={<Lock className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Domains Watched" value="24" icon={<Globe className="h-5 w-5" />} />
        <MetricCard title="Certs Scanned (24h)" value="1,847" icon={<Search className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Anomalies Found" value="7" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Impersonation Alerts" value="3" icon={<Eye className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Anomaly Types (7d)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Typosquatting", v: "3", c: "text-red-400" }, { l: "Homoglyph", v: "2", c: "text-yellow-400" }, { l: "Combosquatting", v: "1", c: "text-cyan-400" }, { l: "Unknown CA", v: "1", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "certificate_feed" && (<div className="space-y-3">{CERTS.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-xs text-white/40">{c.issuer}</span></div><StatusBadge status={c.status} /></div><p className="text-white/90 text-sm font-mono">{c.domain}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{c.san} SANs</span><span>Valid: {c.days}d</span></div></div>))}</div>)}
      {tab === "anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.type}</span></div><StatusBadge status={a.severity} /></div><p className="text-white/90 text-sm font-mono">{a.domain}</p><span className="text-xs text-cyan-400">Confidence: {(a.confidence * 100).toFixed(0)}%</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">CT Monitoring Performance</h3>{[{ m: "Certs Scanned / Day", v: "1,847", t: "+312" }, { m: "Detection Accuracy", v: "96.3%", t: "+1.2%" }, { m: "Avg Alert Latency", v: "4.2 min", t: "-1.8 min" }, { m: "Domain Coverage", v: "100%", t: "stable" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
