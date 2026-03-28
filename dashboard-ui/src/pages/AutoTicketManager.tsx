import { useState } from "react";
import { Ticket, CheckCircle, Clock, AlertTriangle, Users, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "tickets" | "sla" | "routing";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "tickets", label: "Tickets" }, { id: "sla", label: "SLA Tracking" }, { id: "routing", label: "Routing" }];
export default function AutoTicketManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Auto Ticket Manager" subtitle="Auto-create tickets, assign owners, track SLA, auto-close on fix" icon={<Ticket className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Tickets Created" value="234" icon={<Ticket className="h-5 w-5" />} />
      <MetricCard title="Auto-Closed" value="142" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="SLA Compliance" value="94.8%" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Open Now" value="67" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Ticket Lifecycle</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ stage: "Created", count: 234, color: "text-white/70" }, { stage: "Assigned", count: 220, color: "text-cyan-400" }, { stage: "In Progress", count: 67, color: "text-yellow-400" }, { stage: "Auto-Closed", count: 142, color: "text-emerald-400" }].map((s) => (
        <div key={s.stage} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.stage}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "tickets" && (<div className="space-y-3">
      {[{ id: "JIRA-1234", title: "Fix SQLi in /api/users (auto-created)", source: "web_app_scanner", priority: "p0", assignee: "AppSec", status: "in_progress" },
        { id: "SN-5678", title: "Rotate leaked API key (auto-created)", source: "credential_tester", priority: "p0", assignee: "DevOps", status: "auto_closed" },
        { id: "JIRA-1235", title: "Restrict public S3 bucket (auto-created)", source: "cloud_pentest", priority: "p1", assignee: "Cloud Team", status: "auto_closed" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.source}</span></div><StatusBadge status={t.priority} /></div>
        <p className="text-white/90 font-medium">{t.title}</p><p className="text-xs text-white/50">{t.assignee} | <StatusBadge status={t.status} /></p></div>))}</div>)}
    {tab === "sla" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Priority</th><th className="px-4 py-3">SLA</th><th className="px-4 py-3">Avg Resolution</th><th className="px-4 py-3">Compliance</th></tr></thead>
      <tbody>{[
        { priority: "P0 (Critical)", sla: "4 hours", avg: "2.8h", compliance: "96%" },
        { priority: "P1 (High)", sla: "24 hours", avg: "18h", compliance: "94%" },
        { priority: "P2 (Medium)", sla: "7 days", avg: "4.2d", compliance: "91%" },
        { priority: "P3 (Low)", sla: "30 days", avg: "12d", compliance: "98%" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.priority}</td><td className="px-4 py-3 text-white/70">{s.sla}</td><td className="px-4 py-3 text-white/60">{s.avg}</td><td className="px-4 py-3 text-emerald-400">{s.compliance}</td></tr>))}</tbody></table></div>)}
    {tab === "routing" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Auto-Routing Rules</h3>
      {[{ rule: "Web app vulns → AppSec Team", source: "web_app_scanner", tickets: 67, status: "active" },
        { rule: "Cloud misconfigs → Cloud Team", source: "cloud_pentest", tickets: 78, status: "active" },
        { rule: "Credential leaks → DevOps", source: "credential_tester", tickets: 23, status: "active" },
        { rule: "Network vulns → Infra Team", source: "network_pentest", tickets: 45, status: "active" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.rule}</p><p className="text-xs text-white/50">{r.source} | {r.tickets} tickets</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
