import { useState } from "react";
import { Settings, CheckCircle, AlertTriangle, Wrench, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "misconfigs" | "fixes" | "verified";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "misconfigs", label: "Misconfigs" }, { id: "fixes", label: "Fixes Applied" }, { id: "verified", label: "Verified" }];
export default function ConfigRemediation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Config Remediation" subtitle="Auto-fix security misconfigurations — security groups, IAM, encryption, logging" icon={<Settings className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Configs Scanned" value="1.2K" icon={<Eye className="h-5 w-5" />} />
      <MetricCard title="Misconfigs Found" value="47" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Auto-Fixed" value="38" icon={<Wrench className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Verified" value="36" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Misconfig Categories</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ cat: "Network/SG", found: 12, fixed: 11, color: "text-emerald-400" }, { cat: "IAM/Access", found: 18, fixed: 14, color: "text-yellow-400" }, { cat: "Encryption", found: 8, fixed: 8, color: "text-emerald-400" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4"><p className={clsx("font-bold", c.color)}>{c.cat}</p><p className="text-white/50 text-sm mt-1">{c.found} found | {c.fixed} auto-fixed</p></div>))}</div></div>)}
    {tab === "misconfigs" && (<div className="space-y-3">
      {[{ id: "CFG-047", type: "Security group allows 0.0.0.0/0 on port 22", resource: "sg-prod-web", severity: "high", fix: "Restrict to VPN CIDR", status: "auto_fixed" },
        { id: "CFG-046", type: "S3 bucket missing encryption", resource: "data-exports-prod", severity: "high", fix: "Enable AES-256-GCM", status: "auto_fixed" },
        { id: "CFG-045", type: "IAM role with wildcard actions", resource: "LambdaExecRole", severity: "critical", fix: "Scope to required actions", status: "pending_approval" },
      ].map((m) => (<div key={m.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{m.id}</span><span className="text-xs text-white/40 ml-2">{m.resource}</span></div><StatusBadge status={m.severity} /></div>
        <p className="text-white/90 font-medium">{m.type}</p><p className="text-xs text-white/50">Fix: {m.fix} | <StatusBadge status={m.status} /></p></div>))}</div>)}
    {tab === "fixes" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Applied Fixes</h3>
      {[{ fix: "Restricted SSH access to VPN CIDR only", resource: "sg-prod-web", method: "AWS API", time: "0.3s", status: "verified" },
        { fix: "Enabled S3 default encryption (AES-256)", resource: "data-exports-prod", method: "AWS API", time: "0.5s", status: "verified" },
        { fix: "Enabled CloudTrail logging", resource: "us-east-1", method: "AWS API", time: "1.2s", status: "verified" },
      ].map((f, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.fix}</p><p className="text-xs text-white/50">{f.resource} | {f.method} | {f.time}</p></div><StatusBadge status={f.status} /></div>))}</div>)}
    {tab === "verified" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Post-Fix Verification</h3>
      {[{ fix: "SSH access restriction", method: "Re-scan security group", before: "0.0.0.0/0:22 OPEN", after: "10.0.0.0/8:22 only", result: "fixed" },
        { fix: "S3 encryption enabled", method: "Check bucket policy", before: "No encryption", after: "AES-256-GCM", result: "fixed" },
      ].map((v, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{v.fix}</p><p className="text-xs text-white/50">Before: {v.before} → After: {v.after}</p><StatusBadge status={v.result} /></div>))}</div>)}
  </div>);
}
