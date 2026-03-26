import { useState } from "react";
import { Layers, Network, AlertTriangle, Shield, Target, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "vendors" | "correlations" | "situations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "vendors", label: "Vendors" }, { id: "correlations", label: "Correlations" }, { id: "situations", label: "Situations" }];
export default function CrossVendorCorrelator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Cross-Vendor Correlator" subtitle="Unified correlation — Falcon + Defender + Wiz + Splunk + Elastic + Okta" icon={<Layers className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Vendors Connected" value="8" icon={<Network className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Correlations (24h)" value="47" icon={<Target className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Situations Created" value="5" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Kill Chains Mapped" value="3" icon={<Shield className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">THE Differentiator</h3><p className="text-white/70 text-sm mb-4">CrowdStrike only sees Falcon. Palo Alto only sees Cortex. ShieldOps sees everything.</p><div className="grid grid-cols-1 md:grid-cols-4 gap-3">
      {[{ vendor: "CrowdStrike", alerts: 89, correlated: 34 }, { vendor: "Defender", alerts: 67, correlated: 28 }, { vendor: "Splunk/Elastic", alerts: 234, correlated: 47 }, { vendor: "Okta/IAM", alerts: 45, correlated: 12 }].map((v) => (
        <div key={v.vendor} className="card-interactive p-3"><p className="text-white/90 font-medium text-sm">{v.vendor}</p><p className="text-2xl font-bold text-cyan-400 mt-1">{v.correlated}</p><p className="text-xs text-white/40">of {v.alerts} alerts correlated</p></div>))}</div></div>)}
    {tab === "vendors" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Vendor</th><th className="px-4 py-3">Alerts (24h)</th><th className="px-4 py-3">Normalized</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { vendor: "CrowdStrike Falcon", alerts: 89, norm: "OCSF", status: "connected" },
        { vendor: "Microsoft Defender", alerts: 67, norm: "OCSF", status: "connected" },
        { vendor: "Wiz", alerts: 23, norm: "OCSF", status: "connected" },
        { vendor: "Splunk", alerts: 156, norm: "OCSF", status: "connected" },
        { vendor: "Elastic SIEM", alerts: 78, norm: "OCSF", status: "connected" },
        { vendor: "Okta", alerts: 34, norm: "OCSF", status: "connected" },
        { vendor: "AWS CloudTrail", alerts: 45, norm: "OCSF", status: "connected" },
        { vendor: "Microsoft Sentinel", alerts: 12, norm: "OCSF", status: "connected" },
      ].map((v, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{v.vendor}</td><td className="px-4 py-3 text-white/80">{v.alerts}</td><td className="px-4 py-3 text-cyan-400">{v.norm}</td><td className="px-4 py-3"><StatusBadge status={v.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "correlations" && (<div className="space-y-3">
      {[{ entity: "admin@corp.com", vendors: ["Okta", "Falcon", "CloudTrail"], events: 12, confidence: "strong", kill_chain: "T1078 → T1550 → T1530" },
        { entity: "192.168.1.42", vendors: ["Defender", "Splunk", "Elastic"], events: 8, confidence: "moderate", kill_chain: "T1190 → T1059 → T1021" },
        { entity: "web-server-prod", vendors: ["Wiz", "Falcon", "CloudTrail"], events: 5, confidence: "strong", kill_chain: "T1190 → T1078 → T1537" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium font-mono">{c.entity}</p><StatusBadge status={c.confidence} /></div>
        <div className="flex gap-1 mb-1">{c.vendors.map((v) => <span key={v} className="text-xs px-2 py-0.5 rounded bg-white/10 text-white/60">{v}</span>)}</div>
        <p className="text-xs text-white/50">{c.events} events | Kill chain: {c.kill_chain}</p></div>))}</div>)}
    {tab === "situations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Created Situations</h3>
      {[{ id: "SIT-005", title: "Credential Compromise → Cloud Data Exfil", vendors: 3, priority: "p0_active_attack", actions: 2 },
        { id: "SIT-004", title: "Web Server Exploitation → Lateral Movement", vendors: 3, priority: "p1_high_risk", actions: 3 },
        { id: "SIT-003", title: "Insider Data Hoarding Pattern", vendors: 2, priority: "p2_investigation", actions: 1 },
      ].map((s) => (<div key={s.id} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{s.title}</p><p className="text-xs text-white/50">{s.vendors} vendors correlated | {s.actions} recommended actions</p></div><StatusBadge status={s.priority} /></div>))}</div>)}
  </div>);
}
