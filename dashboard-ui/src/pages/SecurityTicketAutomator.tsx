import { useState } from "react";
import { Ticket, AlertTriangle, Clock, CheckCircle, Users, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "active_tickets" | "sla_compliance" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "active_tickets", label: "Active Tickets" },
  { id: "sla_compliance", label: "SLA Compliance" },
  { id: "metrics", label: "Metrics" },
];

const TICKETS = [
  { id: "SEC-4201", title: "Critical CVE in production API gateway", platform: "Jira", priority: "critical", assignee: "security-team", sla: "4h", status: "in_progress" },
  { id: "SEC-4202", title: "Misconfigured S3 bucket public access", platform: "ServiceNow", priority: "high", assignee: "cloud-ops", sla: "8h", status: "open" },
  { id: "SEC-4203", title: "Expired TLS certificate on staging", platform: "Jira", priority: "medium", assignee: "platform-eng", sla: "24h", status: "in_progress" },
  { id: "SEC-4204", title: "Failed compliance scan on PCI segment", platform: "ServiceNow", priority: "high", assignee: "compliance-team", sla: "12h", status: "escalated" },
  { id: "SEC-4205", title: "Suspicious IAM role assumption pattern", platform: "Jira", priority: "critical", assignee: "security-team", sla: "2h", status: "open" },
];

const SLA_DATA = [
  { priority: "Critical", target: "4h", compliance: "92%", breached: 2, total: 26 },
  { priority: "High", target: "8h", compliance: "97%", breached: 1, total: 41 },
  { priority: "Medium", target: "24h", compliance: "99%", breached: 0, total: 63 },
  { priority: "Low", target: "72h", compliance: "100%", breached: 0, total: 28 },
];

export default function SecurityTicketAutomator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Ticket Automator" subtitle="Automated security ticket creation, assignment, and SLA tracking" icon={<Ticket className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Tickets" value="158" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Auto-Created (30d)" value="342" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="SLA Compliance" value="96.8%" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Resolution" value="6.2h" icon={<BarChart3 className="h-5 w-5 text-white/70" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Ticket Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "12", c: "text-red-400" }, { l: "High", v: "34", c: "text-yellow-400" }, { l: "Medium", v: "67", c: "text-cyan-400" }, { l: "Low", v: "45", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "active_tickets" && (<div className="space-y-3">{TICKETS.map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="ml-2 text-xs text-white/40">{t.platform}</span></div><StatusBadge status={t.status} /></div><p className="text-white/90 text-sm">{t.title}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span><Users className="inline h-3 w-3 mr-1" />{t.assignee}</span><span>SLA: {t.sla}</span><StatusBadge status={t.priority} /></div></div>))}</div>)}
      {tab === "sla_compliance" && (<div className="space-y-3">{SLA_DATA.map((s) => (<div key={s.priority} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{s.priority}</p><p className="text-xs text-white/50">Target: {s.target} | {s.breached} breached of {s.total}</p></div><span className={clsx("font-mono text-lg", parseFloat(s.compliance) >= 98 ? "text-emerald-400" : parseFloat(s.compliance) >= 95 ? "text-yellow-400" : "text-red-400")}>{s.compliance}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Automation Performance</h3>{[{ m: "Auto-Creation Rate", v: "94%", t: "+3%" }, { m: "Avg Assignment Time", v: "12s", t: "-8s" }, { m: "Escalation Rate", v: "8.2%", t: "-1.4%" }, { m: "Mean Resolution", v: "6.2h", t: "-1.1h" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
