import { useState } from "react";
import { KeyRound, Users, ShieldAlert, Clock, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "privileged_accounts" | "session_audit" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "privileged_accounts", label: "Privileged Accounts" },
  { id: "session_audit", label: "Session Audit" },
  { id: "metrics", label: "Metrics" },
];

const ACCOUNTS = [
  { id: "PA-001", username: "svc-deploy-prod", type: "Service Account", platform: "AWS", mfa: true, jit: true, risk: "low" },
  { id: "PA-002", username: "admin@corp.local", type: "Domain Admin", platform: "Active Directory", mfa: true, jit: false, risk: "high" },
  { id: "PA-003", username: "root-breakglass", type: "Break Glass", platform: "GCP", mfa: false, jit: false, risk: "critical" },
  { id: "PA-004", username: "k8s-cluster-admin", type: "Cloud IAM", platform: "Kubernetes", mfa: true, jit: true, risk: "medium" },
];

const SESSIONS = [
  { id: "SS-001", account: "admin@corp.local", start: "2026-03-30 02:14", commands: 47, sensitive: 3, status: "suspicious" },
  { id: "SS-002", account: "svc-deploy-prod", start: "2026-03-30 09:30", commands: 12, sensitive: 0, status: "normal" },
  { id: "SS-003", account: "root-breakglass", start: "2026-03-29 23:45", commands: 8, sensitive: 5, status: "critical" },
];

export default function PrivilegeAccessMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Privilege Access Monitor" subtitle="PAM monitoring, session audit, and JIT access enforcement" icon={<KeyRound className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Privileged Accounts" value="156" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="High Risk" value="12" icon={<ShieldAlert className="h-5 w-5 text-red-400" />} />
        <MetricCard title="JIT Enabled" value="68%" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Sessions (24h)" value="89" icon={<Eye className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">PAM Posture</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Standing Access", v: "48", c: "text-yellow-400" }, { l: "JIT Protected", v: "108", c: "text-emerald-400" }, { l: "MFA Enabled", v: "142", c: "text-cyan-400" }, { l: "Abuse Detected", v: "3", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "privileged_accounts" && (<div className="space-y-3">{ACCOUNTS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.type}</span></div><StatusBadge status={a.risk} /></div><p className="text-white/90 text-sm font-mono">{a.username}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{a.platform}</span>{a.mfa && <span className="text-emerald-400">MFA</span>}{a.jit && <span className="text-cyan-400">JIT</span>}{!a.jit && <span className="text-yellow-400">Standing</span>}</div></div>))}</div>)}
      {tab === "session_audit" && (<div className="space-y-3">{SESSIONS.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.start}</span></div><StatusBadge status={s.status} /></div><p className="text-white/90 text-sm font-mono">{s.account}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{s.commands} commands</span><span className={s.sensitive > 0 ? "text-yellow-400" : "text-white/40"}>{s.sensitive} sensitive</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">PAM Metrics</h3>{[{ m: "JIT Adoption Rate", v: "68%", t: "+12%" }, { m: "Standing Access Reduction", v: "31%", t: "+8%" }, { m: "Avg Session Duration", v: "14 min", t: "-3 min" }, { m: "Abuse Detection Rate", v: "96%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
