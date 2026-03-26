import { useState } from "react";
import { Shield, AlertTriangle, CheckCircle, Clock, Activity, RotateCcw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "plans" | "tests" | "gaps";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "plans", label: "DR Plans" }, { id: "tests", label: "Failover Tests" }, { id: "gaps", label: "DR Gaps" }];
export default function DisasterRecovery() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Disaster Recovery" subtitle="DR plan validation, failover testing, and RTO/RPO tracking" icon={<RotateCcw className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="DR Plans" value="8" icon={<Shield className="h-5 w-5" />} />
      <MetricCard title="Tested (90d)" value="5" icon={<CheckCircle className="h-5 w-5" />} />
      <MetricCard title="RTO Compliance" value="87%" icon={<Clock className="h-5 w-5" />} />
      <MetricCard title="Gaps Found" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">DR Readiness</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[{ label: "Avg RTO", value: "18 min", target: "< 30 min" }, { label: "Avg RPO", value: "4 min", target: "< 15 min" }, { label: "Last Full DR Test", value: "12 days ago", target: "< 90 days" }].map((m) => (
          <div key={m.label} className="card-interactive p-4"><p className="text-sm text-white/60">{m.label}</p><p className="text-2xl font-bold text-white mt-1">{m.value}</p><p className="text-xs text-white/40">Target: {m.target}</p></div>))}
      </div></div>)}
    {tab === "plans" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Plan</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Services</th><th className="px-4 py-3">RTO/RPO</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Last Tested</th></tr></thead>
      <tbody>{[
        { name: "Primary DB Failover", type: "Database", svcs: 4, rto: "15m/5m", status: "tested", last: "12 days ago" },
        { name: "Region Failover", type: "Region", svcs: 12, rto: "30m/15m", status: "tested", last: "45 days ago" },
        { name: "API Tier Recovery", type: "Application", svcs: 6, rto: "10m/0m", status: "untested", last: "Never" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{p.name}</td><td className="px-4 py-3 text-white/70">{p.type}</td><td className="px-4 py-3 text-white/80">{p.svcs}</td><td className="px-4 py-3 text-white/70">{p.rto}</td><td className="px-4 py-3"><StatusBadge status={p.status} /></td><td className="px-4 py-3 text-white/50">{p.last}</td></tr>))}</tbody></table></div>)}
    {tab === "tests" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Failover Tests</h3>
      {[{ plan: "Primary DB Failover", result: "success", rto: "14 min", rpo: "3 min", loss: false },
        { plan: "Region Failover", result: "partial", rto: "38 min", rpo: "12 min", loss: false },
      ].map((t, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{t.plan}</p><p className="text-xs text-white/50">RTO: {t.rto} | RPO: {t.rpo} | Data loss: {t.loss ? "Yes" : "No"}</p></div><StatusBadge status={t.result} /></div>))}</div>)}
    {tab === "gaps" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">DR Gaps</h3>
      {[{ gap: "API Tier has no DR plan tested", sev: "high", fix: "Schedule failover test for API tier" },
        { gap: "Region failover exceeded RTO target by 8 min", sev: "medium", fix: "Optimize DNS failover + pre-warm standby" },
      ].map((g, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{g.gap}</p><p className="text-xs text-cyan-400">{g.fix}</p></div><StatusBadge status={g.sev} /></div>))}</div>)}
  </div>);
}
