import { useState } from "react";
import { Network, Shield, AlertTriangle, CheckCircle, Lock, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "zones" | "violations" | "enforcement";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "zones", label: "Network Zones" }, { id: "violations", label: "Violations" }, { id: "enforcement", label: "Enforcement" }];
export default function NetworkSegmentation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Network Segmentation" subtitle="Verify and enforce micro-segmentation policies" icon={<Network className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Zones Monitored" value="12" icon={<Network className="h-5 w-5" />} />
      <MetricCard title="Violations" value="5" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Policies Enforced" value="34" icon={<Lock className="h-5 w-5" />} />
      <MetricCard title="Compliance" value="92%" icon={<Shield className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Zone Compliance</h3>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {[{ zone: "DMZ", flows: 1200, violations: 0 }, { zone: "Internal", flows: 8400, violations: 2 }, { zone: "Restricted", flows: 340, violations: 1 }, { zone: "Public", flows: 4200, violations: 2 }, { zone: "Mgmt", flows: 180, violations: 0 }].map((z) => (
          <div key={z.zone} className="card-interactive p-3 text-center"><p className="text-xs text-white/50">{z.zone}</p><p className="text-xl font-bold text-white">{z.flows}</p><p className={clsx("text-xs", z.violations > 0 ? "text-red-400" : "text-emerald-400")}>{z.violations} violations</p></div>))}
      </div></div>)}
    {tab === "zones" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Zone</th><th className="px-4 py-3">CIDRs</th><th className="px-4 py-3">Services</th><th className="px-4 py-3">Ingress Rules</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { zone: "DMZ", cidr: "10.0.1.0/24", svcs: 4, rules: 12, ok: true },
        { zone: "Internal-Prod", cidr: "10.0.10.0/20", svcs: 28, rules: 45, ok: false },
        { zone: "Restricted-DB", cidr: "10.0.100.0/28", svcs: 3, rules: 8, ok: true },
      ].map((z, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{z.zone}</td><td className="px-4 py-3 font-mono text-xs text-cyan-400">{z.cidr}</td><td className="px-4 py-3 text-white/80">{z.svcs}</td><td className="px-4 py-3 text-white/70">{z.rules}</td><td className="px-4 py-3">{z.ok ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 text-yellow-400" />}</td></tr>))}</tbody></table></div>)}
    {tab === "violations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Segmentation Violations</h3>
      {[{ flow: "worker-pod → restricted-db:5432", type: "Unauthorized cross-zone", sev: "critical", mitre: "T1021" },
        { flow: "public-lb → internal-api:8080", type: "Missing encryption", sev: "high", mitre: "T1557" },
      ].map((v, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium font-mono text-sm">{v.flow}</p><p className="text-xs text-white/50">{v.type} | {v.mitre}</p></div><StatusBadge status={v.sev} /></div>))}</div>)}
    {tab === "enforcement" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Policy Enforcement</h3>
      {[{ policy: "K8s NetworkPolicy: deny-cross-namespace", status: "enforced", zones: 8 },
        { policy: "AWS Security Group: restrict-db-access", status: "enforced", zones: 3 },
        { policy: "Service Mesh: mTLS required", status: "partial", zones: 10 },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.policy}</p><p className="text-xs text-white/50">{p.zones} zones covered</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
