import { useState } from "react";
import { Cloud, Shield, AlertTriangle, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "saas_inventory" | "misconfigurations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "saas_inventory", label: "SaaS Inventory" },
  { id: "misconfigurations", label: "Misconfigurations" },
  { id: "metrics", label: "Metrics" },
];

const APPS = [
  { name: "Slack", users: 1240, oauth: 18, risk: "medium", detail: "3 overprivileged OAuth apps" },
  { name: "Google Workspace", users: 1180, oauth: 42, risk: "high", detail: "External sharing enabled for all" },
  { name: "Salesforce", users: 340, oauth: 8, risk: "low", detail: "SSO enforced, MFA required" },
  { name: "GitHub", users: 280, oauth: 24, risk: "high", detail: "5 repos with public visibility" },
  { name: "Jira", users: 890, oauth: 12, risk: "medium", detail: "API tokens without expiry" },
];

export default function SaasSecurityPosture() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="SaaS Security Posture" subtitle="SaaS application security posture management" icon={<Cloud className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="SaaS Apps" value="47" icon={<Cloud className="h-5 w-5" />} />
        <MetricCard title="OAuth Grants" value="156" icon={<Eye className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Misconfigs" value="34" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Posture Score" value="72/100" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "3", c: "text-red-400" }, { l: "High", v: "12", c: "text-orange-400" }, { l: "Medium", v: "19", c: "text-yellow-400" }, { l: "Low", v: "13", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "saas_inventory" && (<div className="space-y-3">{APPS.map((a) => (<div key={a.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium">{a.name}</span><span className="ml-2 text-xs text-white/40">{a.users} users</span></div><StatusBadge status={a.risk} /></div><p className="text-white/50 text-sm">{a.detail}</p><span className="text-xs text-white/40">{a.oauth} OAuth grants</span></div>))}</div>)}
      {tab === "misconfigurations" && (<div className="card-surface p-6"><h3 className="section-heading">Top Misconfigurations</h3><div className="space-y-2">{[{ issue: "External sharing enabled globally", app: "Google Workspace", severity: "critical" }, { issue: "MFA not enforced for admins", app: "Slack", severity: "high" }, { issue: "Public repository access", app: "GitHub", severity: "high" }, { issue: "API tokens without expiry", app: "Jira", severity: "medium" }].map((m, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70">{m.issue}</span><span className="text-white/40 ml-2">— {m.app}</span></div><StatusBadge status={m.severity} /></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">SSPM Trends</h3>{[{ m: "Posture Score", v: "72/100", t: "+4 vs last month" }, { m: "Shadow SaaS", v: "8 apps", t: "-2 remediated" }, { m: "OAuth Risk", v: "23 risky", t: "+3 new grants" }, { m: "Config Drift", v: "12", t: "-5 fixed" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
