import { useState } from "react";
import { Mail, Shield, CheckCircle, AlertTriangle, Globe, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "domain_status" | "authentication_gaps" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "domain_status", label: "Domain Status" },
  { id: "authentication_gaps", label: "Auth Gaps" },
  { id: "metrics", label: "Metrics" },
];

const DOMAINS = [
  { domain: "company.com", spf: "pass", dkim: "pass", dmarc: "reject", status: "compliant" },
  { domain: "marketing.company.com", spf: "pass", dkim: "pass", dmarc: "quarantine", status: "partial" },
  { domain: "support.company.com", spf: "pass", dkim: "missing", dmarc: "none", status: "non_compliant" },
  { domain: "legacy-app.io", spf: "missing", dkim: "missing", dmarc: "not_set", status: "non_compliant" },
];

const GAPS = [
  { domain: "support.company.com", gap: "DKIM not configured", severity: "high", recommendation: "Deploy DKIM with 2048-bit keys" },
  { domain: "support.company.com", gap: "DMARC policy p=none", severity: "high", recommendation: "Progress to p=quarantine" },
  { domain: "legacy-app.io", gap: "No SPF record", severity: "critical", recommendation: "Publish SPF with authorized senders" },
  { domain: "legacy-app.io", gap: "No DMARC record", severity: "critical", recommendation: "Publish DMARC with p=reject" },
];

export default function EmailAuthenticationAuditor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Email Authentication Auditor" subtitle="DMARC, DKIM, and SPF compliance auditing" icon={<Mail className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Domains Scanned" value="12" icon={<Globe className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Fully Compliant" value="5" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Auth Gaps" value="8" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="DMARC Reject" value="42%" icon={<Shield className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Authentication Coverage</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "SPF Pass", v: "83%", c: "text-emerald-400" }, { l: "DKIM Pass", v: "67%", c: "text-yellow-400" }, { l: "DMARC Reject", v: "42%", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "domain_status" && (<div className="space-y-3">{DOMAINS.map((d) => (<div key={d.domain} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium font-mono">{d.domain}</span><StatusBadge status={d.status} /></div><div className="flex gap-4 mt-2 text-xs"><span className={d.spf === "pass" ? "text-emerald-400" : "text-red-400"}>SPF: {d.spf}</span><span className={d.dkim === "pass" ? "text-emerald-400" : "text-red-400"}>DKIM: {d.dkim}</span><span className={d.dmarc === "reject" ? "text-emerald-400" : d.dmarc === "quarantine" ? "text-yellow-400" : "text-red-400"}>DMARC: {d.dmarc}</span></div></div>))}</div>)}
      {tab === "authentication_gaps" && (<div className="space-y-3">{GAPS.map((g, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{g.domain}</span><StatusBadge status={g.severity} /></div><p className="text-white/90 text-sm">{g.gap}</p><p className="text-xs text-emerald-400 mt-1">{g.recommendation}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Email Auth Metrics</h3>{[{ m: "DMARC Compliance", v: "42%", t: "+8%" }, { m: "SPF Compliance", v: "83%", t: "+5%" }, { m: "DKIM Compliance", v: "67%", t: "+12%" }, { m: "Spoofing Attempts Blocked", v: "1,247", t: "+340" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
