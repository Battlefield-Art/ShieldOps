import { useState } from "react";
import { Mail, Shield, AlertTriangle, Ban } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "threats" | "quarantine" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "threats", label: "Threats" },
  { id: "quarantine", label: "Quarantine" },
  { id: "metrics", label: "Metrics" },
];

const THREATS = [
  { sender: "ceo@evil-corp.ru", subject: "Urgent Wire Transfer", verdict: "bec", confidence: 0.94, detail: "Display name spoofing CEO, DMARC fail" },
  { sender: "support@paypa1.com", subject: "Account Suspended", verdict: "phishing", confidence: 0.91, detail: "Homoglyph domain, credential harvesting link" },
  { sender: "hr@company.com", subject: "Benefits Update.xlsm", verdict: "malware", confidence: 0.97, detail: "Macro-enabled attachment, Emotet dropper" },
  { sender: "newsletter@spam-factory.io", subject: "You Won $1M!", verdict: "spam", confidence: 0.88, detail: "Known spam domain, bulk template" },
  { sender: "admin@internal.co", subject: "Password Reset", verdict: "spoofed", confidence: 0.82, detail: "SPF fail, return-path mismatch" },
];

const QUARANTINE = [
  { id: "Q-001", sender: "ceo@evil-corp.ru", recipient: "finance@co.com", verdict: "bec", action: "Blocked", time: "2 min ago" },
  { id: "Q-002", sender: "hr@company.com", recipient: "all@co.com", verdict: "malware", action: "Quarantined", time: "5 min ago" },
  { id: "Q-003", sender: "support@paypa1.com", recipient: "user@co.com", verdict: "phishing", action: "Quarantined", time: "12 min ago" },
  { id: "Q-004", sender: "newsletter@spam-factory.io", recipient: "user2@co.com", verdict: "spam", action: "Tagged", time: "15 min ago" },
];

export default function EmailSecurityGateway() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Email Security Gateway" subtitle="Email threat analysis, phishing detection, and quarantine management" icon={<Mail className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Emails Scanned" value="12,847" icon={<Mail className="h-5 w-5" />} />
        <MetricCard title="Threats Blocked" value="342" icon={<Shield className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Quarantined" value="89" icon={<Ban className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Auth Failures" value="156" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Distribution</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-4">{[{ l: "Phishing", v: "124", c: "text-red-400" }, { l: "Malware", v: "67", c: "text-orange-400" }, { l: "BEC", v: "23", c: "text-yellow-400" }, { l: "Spam", v: "98", c: "text-blue-400" }, { l: "Spoofed", v: "30", c: "text-purple-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "threats" && (<div className="space-y-3">{THREATS.map((t) => (<div key={t.sender} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{t.sender}</span><span className="ml-2 text-xs text-white/40">{t.subject}</span></div><StatusBadge status={t.verdict === "bec" ? "critical" : t.verdict === "malware" ? "critical" : "high"} /></div><p className="text-white/50 text-sm">{t.detail}</p><span className="text-xs text-white/40">Confidence: {(t.confidence * 100).toFixed(0)}%</span></div>))}</div>)}
      {tab === "quarantine" && (<div className="card-surface p-6"><h3 className="section-heading">Quarantine Queue</h3><div className="space-y-2">{QUARANTINE.map((q) => (<div key={q.id} className="card-interactive p-3 flex items-center justify-between text-sm"><div className="flex-1"><span className="text-white/70 font-mono">{q.sender}</span><span className="text-white/40 ml-2">to {q.recipient}</span></div><div className="flex gap-3 items-center"><StatusBadge status={q.verdict === "malware" || q.verdict === "bec" ? "critical" : "high"} /><span className="text-white/40 text-xs">{q.time}</span></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Gateway Metrics</h3>{[{ m: "Detection Rate", v: "99.2%", t: "+0.3% vs last week" }, { m: "False Positive Rate", v: "0.4%", t: "-0.1%" }, { m: "Avg Scan Time", v: "1.2s", t: "-0.3s" }, { m: "DMARC Pass Rate", v: "87%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
