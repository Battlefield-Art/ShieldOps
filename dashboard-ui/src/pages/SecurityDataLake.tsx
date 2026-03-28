import { useState } from "react";
import { Database, Search, BarChart3, Activity, Filter, Download } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "query" | "sources" | "recent";
const TABS: { id: TabId; label: string }[] = [{ id: "query", label: "Query" }, { id: "sources", label: "Data Sources" }, { id: "recent", label: "Recent Queries" }];
export default function SecurityDataLake() {
  const [tab, setTab] = useState<TabId>("query");
  return (<div className="space-y-6">
    <PageHeader title="Security Data Lake" subtitle="Unified query across all agent data — findings, metrics, audit logs" icon={<Database className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Total Records" value="2.4M" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Sources" value="174" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Queries Today" value="89" icon={<Search className="h-5 w-5" />} />
      <MetricCard title="Avg Response" value="1.2s" icon={<BarChart3 className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "query" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Natural Language Query</h3>
      <div className="bg-white/5 rounded-lg p-4"><textarea className="w-full bg-white/5 border border-white/10 rounded p-3 text-sm text-white/90 placeholder-white/30 h-20" placeholder="e.g., Show me all critical findings from the last 7 days that haven't been remediated..." /><button className="btn-primary mt-3 px-4 py-2 flex items-center gap-2"><Search className="h-4 w-4" /> Query</button></div>
      <div className="card-interactive p-4"><h4 className="text-white/90 font-medium mb-2">Example: "Critical unremediated findings (7d)"</h4><div className="space-y-1 text-sm text-white/60"><p>- 12 critical findings from cloud_pentest (IAM escalation paths)</p><p>- 8 critical findings from web_app_scanner (SQLi, auth bypass)</p><p>- 3 critical findings from credential_tester (leaked credentials)</p><p className="text-cyan-400 mt-2">23 total critical findings | 14 with remediation plans | 9 need attention</p></div></div></div>)}
    {tab === "sources" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Records</th><th className="px-4 py-3">Last Updated</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { src: "Agent Findings", records: "89K", updated: "5 min ago", status: "live" },
        { src: "Agent Metrics", records: "1.2M", updated: "1 min ago", status: "live" },
        { src: "Audit Logs", records: "890K", updated: "Real-time", status: "live" },
        { src: "Scan Results", records: "234K", updated: "12 min ago", status: "live" },
        { src: "Remediation Records", records: "45K", updated: "30 min ago", status: "live" },
        { src: "Ticket Data", records: "12K", updated: "1h ago", status: "live" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.src}</td><td className="px-4 py-3 text-white/80">{s.records}</td><td className="px-4 py-3 text-white/50">{s.updated}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "recent" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Queries</h3>
      {[{ query: "Critical findings by cloud provider last 30 days", type: "aggregate", records: 234, time: "0.8s" },
        { query: "Remediation SLA compliance by team", type: "aggregate", records: 89, time: "1.1s" },
        { query: "All findings for 10.0.2.42 across all scanners", type: "search", records: 12, time: "0.3s" },
        { query: "MITRE coverage trend last 90 days", type: "trend", records: 45, time: "1.5s" },
      ].map((q, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{q.query}</p><p className="text-xs text-white/50">{q.type} | {q.records} records | {q.time}</p></div>))}</div>)}
  </div>);
}
