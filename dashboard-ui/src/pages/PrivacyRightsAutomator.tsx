import { useState } from "react";
import { FileText, Search, Shield, CheckCircle, Users, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "active_requests" | "request_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "active_requests", label: "Active Requests" },
  { id: "request_status", label: "Request Status" },
  { id: "metrics", label: "Metrics" },
];

const REQUESTS = [
  { id: "DSR-001", subject: "j.doe@acme.com", type: "Deletion", regulation: "GDPR", status: "processing", systems: 12 },
  { id: "DSR-002", subject: "m.smith@corp.io", type: "Access", regulation: "CCPA", status: "locating", systems: 8 },
  { id: "DSR-003", subject: "a.chen@startup.dev", type: "Portability", regulation: "GDPR", status: "completed", systems: 5 },
  { id: "DSR-004", subject: "r.kumar@ent.co", type: "Rectification", regulation: "LGPD", status: "verifying", systems: 15 },
];

const STATUS_ITEMS = [
  { id: "DSR-001", stage: "Process Action", progress: 65, deadline: "2d remaining" },
  { id: "DSR-002", stage: "Locate Data", progress: 30, deadline: "5d remaining" },
  { id: "DSR-003", stage: "Complete", progress: 100, deadline: "Fulfilled" },
  { id: "DSR-004", stage: "Verify Completion", progress: 80, deadline: "1d remaining" },
];

export default function PrivacyRightsAutomator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Privacy Rights Automator" subtitle="DSAR/CCPA/GDPR request automation and compliance" icon={<FileText className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Requests" value="7" icon={<Search className="h-5 w-5" />} />
        <MetricCard title="Fulfilled (30d)" value="34" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Avg Fulfillment" value="2.1d" icon={<Users className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Compliance Rate" value="97%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Request Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Deletion", v: "18", c: "text-red-400" }, { l: "Access", v: "12", c: "text-cyan-400" }, { l: "Portability", v: "6", c: "text-emerald-400" }, { l: "Rectification", v: "5", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "active_requests" && (<div className="space-y-3">{REQUESTS.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.regulation}</span></div><StatusBadge status={r.status} /></div><p className="text-white/90 text-sm">{r.subject}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Type: {r.type}</span><span>{r.systems} systems</span></div></div>))}</div>)}
      {tab === "request_status" && (<div className="space-y-3">{STATUS_ITEMS.map((item) => (<div key={item.id} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{item.id}</span><span className="text-xs text-white/50">{item.deadline}</span></div><p className="text-white/90 text-sm mb-2">{item.stage}</p><div className="w-full bg-white/10 rounded-full h-2"><div className="bg-cyan-500 h-2 rounded-full" style={{ width: `${item.progress}%` }} /></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Fulfillment Performance</h3>{[{ m: "Compliance Rate", v: "97%", t: "+2%" }, { m: "Avg Fulfillment Time", v: "2.1 days", t: "-0.4 days" }, { m: "Systems per Request", v: "9.3", t: "+1.2" }, { m: "PII Categories Found", v: "14", t: "+3" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
