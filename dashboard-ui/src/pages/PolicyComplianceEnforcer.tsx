import { useState } from "react";
import { Scale, Shield, FileCheck, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "policy_decisions" | "exemptions" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "policy_decisions", label: "Policy Decisions" },
  { id: "exemptions", label: "Exemptions" },
  { id: "metrics", label: "Metrics" },
];

const DECISIONS = [
  { id: "PCE-001", resource: "iam:role/AdminAccess", action: "deny", framework: "SOC 2", violations: 2, actor: "ci-pipeline", ts: "2 min ago" },
  { id: "PCE-002", resource: "s3:prod-data-lake", action: "allow", framework: "HIPAA", violations: 0, actor: "data-team", ts: "5 min ago" },
  { id: "PCE-003", resource: "k8s:deployment/api-v2", action: "warn", framework: "PCI DSS", violations: 1, actor: "deploy-bot", ts: "12 min ago" },
  { id: "PCE-004", resource: "rds:prod-main", action: "require_approval", framework: "GDPR", violations: 1, actor: "dba-service", ts: "18 min ago" },
];

const EXEMPTIONS = [
  { id: "EXE-001", policy: "no-public-s3", resource: "s3:marketing-assets", reason: "Public CDN bucket", expires: "2026-06-01", status: "active" },
  { id: "EXE-002", policy: "mfa-required", resource: "iam:ci-runner", reason: "Service account", expires: "2026-04-15", status: "active" },
  { id: "EXE-003", policy: "encryption-at-rest", resource: "ebs:dev-scratch", reason: "Dev environment", expires: "2026-03-31", status: "expiring" },
];

export default function PolicyComplianceEnforcer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Policy Compliance Enforcer" subtitle="Real-time policy enforcement and compliance gating" icon={<Scale className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Decisions (24h)" value="847" icon={<FileCheck className="h-5 w-5" />} />
        <MetricCard title="Compliance Rate" value="96.2%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Violations (24h)" value="32" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Active Exemptions" value="8" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Enforcement Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Allow", v: "815", c: "text-emerald-400" }, { l: "Deny", v: "18", c: "text-red-400" }, { l: "Warn", v: "9", c: "text-yellow-400" }, { l: "Require Approval", v: "5", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "policy_decisions" && (<div className="space-y-3">{DECISIONS.map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="ml-2 text-xs text-white/40">{d.ts}</span></div><StatusBadge status={d.action === "deny" ? "critical" : d.action === "warn" ? "warning" : d.action === "require_approval" ? "medium" : "active"} /></div><p className="text-white/90 text-sm font-mono">{d.resource}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{d.framework}</span><span>Actor: {d.actor}</span><span className={d.violations > 0 ? "text-yellow-400" : "text-white/40"}>{d.violations} violations</span></div></div>))}</div>)}
      {tab === "exemptions" && (<div className="space-y-3">{EXEMPTIONS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.policy}</span></div><StatusBadge status={e.status} /></div><p className="text-white/90 text-sm font-mono">{e.resource}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{e.reason}</span><span>Expires: {e.expires}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Enforcement Metrics</h3>{[{ m: "Compliance Rate", v: "96.2%", t: "+1.4%" }, { m: "Avg Decision Latency", v: "12ms", t: "-3ms" }, { m: "Policies Loaded", v: "142", t: "+8" }, { m: "Audit Coverage", v: "100%", t: "Steady" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
