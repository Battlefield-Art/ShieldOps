import { useState } from "react";
import { Bell, GitBranch, Shield, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "alert_queue" | "routing_rules" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "alert_queue", label: "Alert Queue" },
  { id: "routing_rules", label: "Routing Rules" },
  { id: "metrics", label: "Metrics" },
];

const ALERTS = [
  { id: "ALR-001", title: "Malware detected on endpoint SRV-042", category: "Malware", priority: "p1_critical", team: "SOC Tier 2", ack: true },
  { id: "ALR-002", title: "Unusual IAM role creation in prod account", category: "Intrusion", priority: "p2_high", team: "Cloud Security", ack: false },
  { id: "ALR-003", title: "DLP policy violation — PII in S3 bucket", category: "Data Leak", priority: "p2_high", team: "Data Security", ack: true },
  { id: "ALR-004", title: "Failed MFA attempts from suspicious IP", category: "Anomaly", priority: "p3_medium", team: "Identity Team", ack: true },
];

const RULES = [
  { id: "RL-001", category: "Malware", destination: "SOC Tier 2", channel: "PagerDuty", sla: "15m" },
  { id: "RL-002", category: "Intrusion", destination: "Cloud Security", channel: "PagerDuty", sla: "15m" },
  { id: "RL-003", category: "Data Leak", destination: "Data Security", channel: "Slack", sla: "30m" },
  { id: "RL-004", category: "Policy Violation", destination: "Compliance", channel: "Email", sla: "4h" },
  { id: "RL-005", category: "Anomaly", destination: "SOC Tier 1", channel: "Slack", sla: "1h" },
];

export default function SecurityAlertRouter() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Alert Router" subtitle="Intelligent security alert routing and team assignment" icon={<Bell className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Alerts Today" value="147" icon={<Bell className="h-5 w-5" />} />
        <MetricCard title="Routed" value="142" icon={<GitBranch className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Acknowledged" value="138" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Response" value="8.3m" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Alerts by Category</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Malware", v: "12", c: "text-red-400" }, { l: "Intrusion", v: "8", c: "text-yellow-400" }, { l: "Data Leak", v: "5", c: "text-cyan-400" }, { l: "Anomaly", v: "122", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "alert_queue" && (<div className="space-y-3">{ALERTS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.category}</span></div><StatusBadge status={a.priority.replace("p1_", "").replace("p2_", "").replace("p3_", "")} /></div><p className="text-white/90 text-sm">{a.title}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Team: {a.team}</span><span className={a.ack ? "text-emerald-400" : "text-yellow-400"}>{a.ack ? "Acknowledged" : "Pending"}</span></div></div>))}</div>)}
      {tab === "routing_rules" && (<div className="space-y-3">{RULES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="text-xs text-white/40">{r.channel}</span></div><p className="text-white/90 text-sm">{r.category} → {r.destination}</p><span className="text-xs text-white/50">SLA: {r.sla}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Routing Performance</h3>{[{ m: "SLA Compliance", v: "94%", t: "+3%" }, { m: "Avg Response Time", v: "8.3m", t: "-2.1m" }, { m: "Acknowledgment Rate", v: "97%", t: "+1%" }, { m: "Misroute Rate", v: "2.1%", t: "-0.8%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
