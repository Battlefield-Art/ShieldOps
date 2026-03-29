import { useState } from "react";
import { Shield, AlertTriangle, CheckCircle, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "rules" | "violations" | "compliance";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "rules", label: "Rules" }, { id: "violations", label: "Violations" }, { id: "compliance", label: "Compliance" }];
export default function FirewallRuleAuditor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Firewall Rule Auditor" subtitle="Audit firewall rules — detect overly permissive, shadow, and expired rules" icon={<Shield className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Rules Audited" value="1,247" icon={<Shield className="h-5 w-5" />} />
      <MetricCard title="Violations" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Compliance" value="94.2%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Risk Score" value="Low" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Rule Distribution by Provider</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ provider: "AWS SG", rules: 523, violations: 8, color: "text-cyan-400" }, { provider: "Azure NSG", rules: 412, violations: 11, color: "text-yellow-400" }, { provider: "GCP Firewall", rules: 312, violations: 4, color: "text-emerald-400" }].map((p) => (
        <div key={p.provider} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{p.provider}</p><p className={clsx("text-2xl font-bold mt-1", p.color)}>{p.rules}</p><p className="text-xs text-white/40">{p.violations} violations</p></div>))}</div></div>)}
    {tab === "rules" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Rule ID</th><th className="px-4 py-3">Source</th><th className="px-4 py-3">Destination</th><th className="px-4 py-3">Action</th><th className="px-4 py-3">Risk</th></tr></thead>
      <tbody>{[{ id: "sg-rule-001", src: "0.0.0.0/0", dst: "10.0.0.0/8:22", action: "allow", risk: "high" }, { id: "nsg-rule-012", src: "10.0.0.0/8", dst: "10.1.0.0/16:443", action: "allow", risk: "low" }, { id: "gcp-fw-003", src: "0.0.0.0/0", dst: "10.0.0.0/8:3389", action: "allow", risk: "critical" }].map((r, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{r.id}</td><td className="px-4 py-3 text-white/80">{r.src}</td><td className="px-4 py-3 text-white/80">{r.dst}</td><td className="px-4 py-3 text-white/70">{r.action}</td><td className="px-4 py-3"><StatusBadge status={r.risk} /></td></tr>))}</tbody></table></div>)}
    {tab === "violations" && (<div className="space-y-3">{[{ rule: "sg-rule-001", type: "Overly Permissive", detail: "SSH open to world (0.0.0.0/0:22)", severity: "high" }, { rule: "gcp-fw-003", type: "Overly Permissive", detail: "RDP open to world (0.0.0.0/0:3389)", severity: "critical" }].map((v, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{v.rule}</span><StatusBadge status={v.severity} /></div><p className="text-white/90 font-medium">{v.type}</p><p className="text-xs text-white/50">{v.detail}</p></div>))}</div>)}
    {tab === "compliance" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Compliance by Framework</h3>{[{ fw: "CIS Benchmark", score: 94, status: "on_target" }, { fw: "PCI DSS", score: 91, status: "on_target" }, { fw: "NIST 800-53", score: 88, status: "at_risk" }].map((c, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.fw}</p><p className="text-xs text-white/50">Score: {c.score}%</p></div><StatusBadge status={c.status} /></div>))}</div>)}
  </div>);
}
