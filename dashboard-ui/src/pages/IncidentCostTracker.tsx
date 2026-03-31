import { useState } from "react";
import { DollarSign, AlertTriangle, TrendingUp, FileText, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "cost_breakdown" | "regulatory_exposure" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "cost_breakdown", label: "Cost Breakdown" },
  { id: "regulatory_exposure", label: "Regulatory Exposure" },
  { id: "metrics", label: "Metrics" },
];

const INCIDENTS = [
  { id: "INC-2024-042", type: "Data Breach", direct: "$1.2M", indirect: "$3.4M", total: "$4.6M", status: "critical" },
  { id: "INC-2024-039", type: "Ransomware", direct: "$800K", indirect: "$1.1M", total: "$1.9M", status: "high" },
  { id: "INC-2024-035", type: "DDoS", direct: "$120K", indirect: "$280K", total: "$400K", status: "medium" },
  { id: "INC-2024-031", type: "Insider Threat", direct: "$340K", indirect: "$890K", total: "$1.23M", status: "high" },
];

export default function IncidentCostTracker() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Incident Cost Tracker" subtitle="Security incident financial impact tracking" icon={<DollarSign className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="YTD Cost" value="$8.13M" icon={<DollarSign className="h-5 w-5" />} />
        <MetricCard title="Active Incidents" value="4" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Regulatory Fines" value="$2.1M" icon={<FileText className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Insurance Coverage" value="68%" icon={<TrendingUp className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Cost Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Direct Costs", v: "$2.46M", c: "text-red-400" }, { l: "Indirect Costs", v: "$5.67M", c: "text-orange-400" }, { l: "Regulatory", v: "$2.1M", c: "text-yellow-400" }, { l: "Insured", v: "$5.5M", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "cost_breakdown" && (<div className="space-y-3">{INCIDENTS.map((inc) => (<div key={inc.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{inc.id}</span><span className="ml-2 text-xs text-white/40">{inc.type}</span></div><StatusBadge status={inc.status} /></div><div className="flex gap-4 text-xs text-white/40"><span>Direct: {inc.direct}</span><span>Indirect: {inc.indirect}</span><span className="text-cyan-400">Total: {inc.total}</span></div></div>))}</div>)}
      {tab === "regulatory_exposure" && (<div className="card-surface p-6"><h3 className="section-heading">Regulatory Risk</h3><div className="space-y-2">{[{ reg: "GDPR — Data Breach Notification", exposure: "$1.2M", status: "pending" }, { reg: "HIPAA — PHI Exposure", exposure: "$500K", status: "under_review" }, { reg: "PCI-DSS — Card Data Compromise", exposure: "$400K", status: "resolved" }, { reg: "SOX — Audit Finding", exposure: "$0", status: "compliant" }].map((r, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70">{r.reg}</span></div><div className="flex gap-3"><span className="text-cyan-400 font-mono">{r.exposure}</span><StatusBadge status={r.status === "compliant" ? "healthy" : r.status === "resolved" ? "low" : "high"} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Financial Metrics</h3>{[{ m: "Cost per Record", v: "$164", t: "industry avg: $180" }, { m: "MTTR (Financial)", v: "34 days", t: "-8 days vs last quarter" }, { m: "Insurance ROI", v: "3.2x", t: "premiums vs. payouts" }, { m: "Cost Avoidance", v: "$12.4M", t: "estimated savings from prevention" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
