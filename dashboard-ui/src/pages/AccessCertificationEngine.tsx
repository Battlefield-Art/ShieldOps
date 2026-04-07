import { useState } from "react";
import { UserCheck, Users, AlertTriangle, ClipboardCheck, Scale } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "entitlements" | "review_campaigns" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "entitlements", label: "Entitlements" },
  { id: "review_campaigns", label: "Review Campaigns" },
  { id: "metrics", label: "Metrics" },
];

const ENTITLEMENTS = [
  { id: "ENT-001", user: "jsmith@corp.io", resource: "AWS Production", role: "Admin", lastUsed: "Never", risk: "critical" },
  { id: "ENT-002", user: "svc-deploy@corp.io", resource: "K8s Cluster", role: "cluster-admin", lastUsed: "2 days ago", risk: "high" },
  { id: "ENT-003", user: "analyst@corp.io", resource: "BigQuery Dataset", role: "dataEditor", lastUsed: "45 days ago", risk: "medium" },
  { id: "ENT-004", user: "dev@corp.io", resource: "GitHub Org", role: "Owner", lastUsed: "1 day ago", risk: "high" },
  { id: "ENT-005", user: "intern@corp.io", resource: "Prod Database", role: "db_owner", lastUsed: "Never", risk: "critical" },
];

const CAMPAIGNS = [
  { id: "RC-001", reviewer: "Engineering Manager", items: 47, status: "active", rubberStamp: 12, dueIn: "5 days" },
  { id: "RC-002", reviewer: "Security Lead", items: 23, status: "active", rubberStamp: 2, dueIn: "3 days" },
  { id: "RC-003", reviewer: "Platform Manager", items: 31, status: "completed", rubberStamp: 18, dueIn: "done" },
];

export default function AccessCertificationEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Access Certification Engine" subtitle="Automated access reviews with rubber-stamp detection" icon={<UserCheck className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Entitlements" value="2,847" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Excess Permissions" value="312" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="SOD Violations" value="18" icon={<Scale className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Review Completion" value="78%" icon={<ClipboardCheck className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Access Risk Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical Excess", v: "47", c: "text-red-400" }, { l: "High Risk", v: "128", c: "text-yellow-400" }, { l: "Medium Risk", v: "137", c: "text-cyan-400" }, { l: "SOD Conflicts", v: "18", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "entitlements" && (<div className="space-y-3">{ENTITLEMENTS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.resource}</span></div><StatusBadge status={e.risk} /></div><p className="text-white/90 text-sm">{e.user}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Role: {e.role}</span><span className={e.lastUsed === "Never" ? "text-red-400" : "text-white/40"}>Last used: {e.lastUsed}</span></div></div>))}</div>)}
      {tab === "review_campaigns" && (<div className="space-y-3">{CAMPAIGNS.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-xs text-white/40">{c.reviewer}</span></div><StatusBadge status={c.status} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{c.items} items</span><span className={c.rubberStamp > 10 ? "text-yellow-400" : "text-white/40"}>Rubber-stamps: {c.rubberStamp}</span><span>Due: {c.dueIn}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Certification Performance</h3>{[{ m: "Review Completion Rate", v: "78%", t: "+5%" }, { m: "Rubber-Stamp Detection", v: "32 flagged", t: "+8" }, { m: "Avg Review Time", v: "2.3 min", t: "-0.5 min" }, { m: "Revocations Executed", v: "89", t: "+12" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
