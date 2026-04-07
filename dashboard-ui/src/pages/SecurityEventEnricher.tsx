import { useState } from "react";
import { Zap, Search, Shield, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "enrichment_pipeline" | "event_routing" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "enrichment_pipeline", label: "Enrichment Pipeline" },
  { id: "event_routing", label: "Event Routing" },
  { id: "metrics", label: "Metrics" },
];

const EVENTS = [
  { id: "EVT-001", source: "CrowdStrike EDR", type: "Process Execution", priority: "critical", iocs: 3, enriched: true },
  { id: "EVT-002", source: "AWS CloudTrail", type: "IAM Role Assumption", priority: "high", iocs: 1, enriched: true },
  { id: "EVT-003", source: "Splunk SIEM", type: "Firewall Block", priority: "medium", iocs: 0, enriched: true },
  { id: "EVT-004", source: "Azure AD", type: "Impossible Travel", priority: "high", iocs: 2, enriched: true },
];

const ROUTING = [
  { id: "RT-001", event: "EVT-001", destination: "SOC Tier 2", channel: "PagerDuty", sla: "15m", status: "acknowledged" },
  { id: "RT-002", event: "EVT-002", destination: "Cloud Security", channel: "Slack", sla: "30m", status: "pending" },
  { id: "RT-003", event: "EVT-003", destination: "Network Ops", channel: "Email", sla: "4h", status: "acknowledged" },
  { id: "RT-004", event: "EVT-004", destination: "Identity Team", channel: "PagerDuty", sla: "15m", status: "acknowledged" },
];

export default function SecurityEventEnricher() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Event Enricher" subtitle="Real-time security event enrichment and routing pipeline" icon={<Zap className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Events/Hour" value="12,480" icon={<Zap className="h-5 w-5" />} />
        <MetricCard title="Enrichment Rate" value="98.2%" icon={<Search className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Critical Events" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Avg Enrichment" value="1.2s" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Pipeline Status by Source</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "SIEM", v: "4,820", c: "text-cyan-400" }, { l: "EDR", v: "3,610", c: "text-emerald-400" }, { l: "Cloud", v: "2,450", c: "text-yellow-400" }, { l: "Identity", v: "1,600", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "enrichment_pipeline" && (<div className="space-y-3">{EVENTS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.source}</span></div><StatusBadge status={e.priority} /></div><p className="text-white/90 text-sm">{e.type}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className={e.iocs > 0 ? "text-red-400" : "text-white/40"}>{e.iocs} IOC matches</span><span className="text-emerald-400">Enriched</span></div></div>))}</div>)}
      {tab === "event_routing" && (<div className="space-y-3">{ROUTING.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.event}</span></div><StatusBadge status={r.status} /></div><p className="text-white/90 text-sm">{r.destination} via {r.channel}</p><span className="text-xs text-white/50">SLA: {r.sla}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Enrichment Performance</h3>{[{ m: "Enrichment Throughput", v: "12.4K/hr", t: "+1.2K" }, { m: "IOC Match Rate", v: "4.8%", t: "+0.3%" }, { m: "Avg Enrichment Latency", v: "1.2s", t: "-0.3s" }, { m: "Routing Accuracy", v: "96%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
