import { useState } from "react";
import { FileSearch, Shield, AlertTriangle, CheckCircle, Eye, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "changes" | "compliance" | "baselines";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "changes", label: "Changes" }, { id: "compliance", label: "Compliance" }, { id: "baselines", label: "Baselines" }];
export default function FileIntegrityMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="File Integrity Monitor" subtitle="AI-enhanced FIM with LLM context analysis — system configs, AI models, K8s manifests" icon={<FileSearch className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Files Monitored" value="12.4K" icon={<Eye className="h-5 w-5" />} />
      <MetricCard title="Changes (24h)" value="47" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Critical Changes" value="3" icon={<Shield className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Compliance" value="98.1%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Changes by Impact</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ impact: "Critical System", count: 3, color: "text-red-400" }, { impact: "Security Config", count: 8, color: "text-yellow-400" }, { impact: "Application", count: 12, color: "text-white/70" }, { impact: "Benign", count: 24, color: "text-white/40" }].map((i) => (
        <div key={i.impact} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{i.impact}</p><p className={clsx("text-3xl font-bold mt-1", i.color)}>{i.count}</p></div>))}</div></div>)}
    {tab === "changes" && (<div className="space-y-3">
      {[{ file: "/etc/shadow", type: "modified", impact: "critical_system", detail: "Password hash changed for root user", auto: "Alerted + rolled back" },
        { file: "models/claude-ft-v3.bin", type: "modified", impact: "critical_system", detail: "AI model weights modified outside deployment", auto: "Alerted + quarantined" },
        { file: "/etc/kubernetes/manifests/kube-apiserver.yaml", type: "modified", impact: "security_config", detail: "API server auth config changed", auto: "Alerted" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="font-mono text-sm text-cyan-400">{c.file}</p><StatusBadge status={c.impact} /></div>
        <p className="text-white/80 text-sm">{c.detail}</p><p className="text-xs text-white/50">Type: {c.type} | Action: {c.auto}</p></div>))}</div>)}
    {tab === "compliance" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">FIM Compliance</h3>
      {[{ framework: "PCI DSS 11.5", requirement: "Monitor critical system files", status: "compliant", evidence: "12,400 files monitored" },
        { framework: "SOC 2 CC6.1", requirement: "Detect unauthorized changes", status: "compliant", evidence: "3 critical changes detected and remediated" },
        { framework: "HIPAA 164.312(b)", requirement: "Audit controls for PHI systems", status: "compliant", evidence: "Full audit trail maintained" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.framework}</p><p className="text-xs text-white/50">{c.requirement} | {c.evidence}</p></div><StatusBadge status={c.status} /></div>))}</div>)}
    {tab === "baselines" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Path</th><th className="px-4 py-3">Files</th><th className="px-4 py-3">Last Scan</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { path: "/etc/*", files: 342, scan: "5 min ago", status: "baseline_current" },
        { path: "AI models", files: 23, scan: "15 min ago", status: "baseline_current" },
        { path: "K8s manifests", files: 89, scan: "10 min ago", status: "baseline_current" },
        { path: "Terraform state", files: 12, scan: "30 min ago", status: "baseline_current" },
      ].map((b, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-xs text-white/70">{b.path}</td><td className="px-4 py-3 text-white/80">{b.files}</td><td className="px-4 py-3 text-white/50">{b.scan}</td><td className="px-4 py-3"><StatusBadge status={b.status} /></td></tr>))}</tbody></table></div>)}
  </div>);
}
