import { useState } from "react";
import { Settings, Shield, AlertTriangle, CheckCircle, XCircle, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "configs" | "drift" | "remediation";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "configs", label: "Config Status" }, { id: "drift", label: "Drift Detection" }, { id: "remediation", label: "Remediation" }];
export default function ConfigValidator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Config Validator" subtitle="Validate infrastructure configs against golden baselines" icon={<Settings className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Configs Tracked" value="186" icon={<Settings className="h-5 w-5" />} />
      <MetricCard title="Drifts Detected" value="8" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Compliance" value="96%" icon={<Shield className="h-5 w-5" />} />
      <MetricCard title="Auto-Fixed" value="5" icon={<RefreshCw className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Compliance by Source</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[{ src: "Kubernetes", configs: 82, compliant: 79 }, { src: "Terraform", configs: 45, compliant: 43 }, { src: "Helm", configs: 28, compliant: 27 }, { src: "Docker", configs: 18, compliant: 17 }, { src: "Cloud IAM", configs: 13, compliant: 12 }].map((s) => (
          <div key={s.src} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><span className="text-sm text-white/60">{s.src}</span><span className="text-sm text-white/70">{s.compliant}/{s.configs}</span></div>
          <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${(s.compliant / s.configs) * 100}%` }} /></div></div>))}
      </div></div>)}
    {tab === "configs" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Resource</th><th className="px-4 py-3">Source</th><th className="px-4 py-3">Compliant</th><th className="px-4 py-3">Last Validated</th></tr></thead>
      <tbody>{[
        { name: "api-gateway Deployment", src: "Kubernetes", ok: true, last: "2 min ago" },
        { name: "vpc-main.tf", src: "Terraform", ok: true, last: "15 min ago" },
        { name: "redis-cluster HPA", src: "Kubernetes", ok: false, last: "8 min ago" },
        { name: "iam-roles.tf", src: "Terraform", ok: false, last: "22 min ago" },
      ].map((c, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{c.name}</td><td className="px-4 py-3 text-white/70">{c.src}</td><td className="px-4 py-3">{c.ok ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-red-400" />}</td><td className="px-4 py-3 text-white/50">{c.last}</td></tr>))}</tbody></table></div>)}
    {tab === "drift" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detected Drifts</h3>
      {[{ resource: "redis-cluster HPA", field: "maxReplicas", expected: "8", actual: "16", sev: "medium", fixable: true },
        { resource: "iam-roles.tf", field: "assume_role_policy", expected: "restricted", actual: "wildcard (*)", sev: "critical", fixable: false },
        { resource: "nginx-ingress ConfigMap", field: "proxy-body-size", expected: "10m", actual: "100m", sev: "low", fixable: true },
      ].map((d, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium">{d.resource} → {d.field}</p><div className="flex gap-4 text-xs mt-1"><span className="text-emerald-400">Expected: {d.expected}</span><span className="text-red-400">Actual: {d.actual}</span></div></div><StatusBadge status={d.sev} /></div>
        <p className="text-xs text-white/40">{d.fixable ? "Auto-fixable" : "Manual fix required"}</p></div>))}</div>)}
    {tab === "remediation" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Remediation Log</h3>
      {[{ action: "Revert maxReplicas to 8", target: "redis-cluster HPA", status: "completed", when: "5 min ago" },
        { action: "Revert proxy-body-size to 10m", target: "nginx-ingress ConfigMap", status: "completed", when: "12 min ago" },
        { action: "Restrict assume_role_policy", target: "iam-roles.tf", status: "pending", when: "Manual review required" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.target} | {r.when}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
