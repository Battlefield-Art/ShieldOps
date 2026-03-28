import { useState } from "react";
import { RefreshCw, Calendar, Activity, Shield, Clock, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "schedule" | "running" | "history";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "schedule", label: "Schedule" }, { id: "running", label: "Running Now" }, { id: "history", label: "History" }];
export default function ContinuousScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Continuous Scanner" subtitle="Security testing never stops — automated scheduling across all agents" icon={<RefreshCw className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Scans Today" value="24" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Running Now" value="3" icon={<RefreshCw className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Coverage" value="98%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Next Scan" value="12 min" icon={<Clock className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Scan Coverage</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "Network", freq: "Daily", last: "2h ago", next: "22h", color: "text-emerald-400" }, { type: "Web Apps", freq: "On deploy", last: "45m ago", next: "On next deploy", color: "text-cyan-400" }, { type: "Cloud", freq: "Hourly", last: "12m ago", next: "48m", color: "text-emerald-400" }].map((s) => (
        <div key={s.type} className="card-interactive p-4"><p className={clsx("font-bold", s.color)}>{s.type}</p><p className="text-xs text-white/50 mt-1">Frequency: {s.freq}</p><p className="text-xs text-white/40">Last: {s.last} | Next: {s.next}</p></div>))}</div></div>)}
    {tab === "schedule" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Scan</th><th className="px-4 py-3">Agent</th><th className="px-4 py-3">Frequency</th><th className="px-4 py-3">Next Run</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { scan: "Network Pentest", agent: "network_pentest", freq: "Daily 2am", next: "2am", status: "scheduled" },
        { scan: "Web App Scan", agent: "web_app_scanner", freq: "On deploy", next: "On trigger", status: "watching" },
        { scan: "Cloud Security", agent: "cloud_pentest", freq: "Hourly", next: "48 min", status: "scheduled" },
        { scan: "API Security", agent: "api_pentest", freq: "Daily 4am", next: "4am", status: "scheduled" },
        { scan: "Credential Check", agent: "credential_tester", freq: "Daily 6am", next: "6am", status: "scheduled" },
        { scan: "Compliance Scan", agent: "compliance_gap_analyzer", freq: "Weekly Mon", next: "Monday", status: "scheduled" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.scan}</td><td className="px-4 py-3 text-white/60">{s.agent}</td><td className="px-4 py-3 text-white/70">{s.freq}</td><td className="px-4 py-3 text-white/50">{s.next}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "running" && (<div className="space-y-3">
      {[{ scan: "Cloud Security Audit", agent: "cloud_pentest", started: "12 min ago", progress: "67%", status: "running" },
        { scan: "Web App OWASP Scan", agent: "web_app_scanner", started: "25 min ago", progress: "89%", status: "running" },
        { scan: "Credential Rotation Check", agent: "credential_tester", started: "5 min ago", progress: "34%", status: "running" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.scan}</p><p className="text-xs text-white/50">{r.agent} | Started: {r.started}</p></div><div className="flex items-center gap-2"><span className="text-cyan-400 font-mono">{r.progress}</span><StatusBadge status={r.status} /></div></div>))}</div>)}
    {tab === "history" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Scans (24h)</h3>
      {[{ scan: "Network Pentest — Daily", findings: 12, duration: "45 min", status: "completed" },
        { scan: "Cloud Security — Hourly #23", findings: 3, duration: "8 min", status: "completed" },
        { scan: "API Pentest — Daily", findings: 5, duration: "22 min", status: "completed" },
        { scan: "Credential Check — Daily", findings: 2, duration: "4 min", status: "completed" },
      ].map((h, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{h.scan}</p><p className="text-xs text-white/50">{h.findings} findings | {h.duration}</p></div><StatusBadge status={h.status} /></div>))}</div>)}
  </div>);
}
