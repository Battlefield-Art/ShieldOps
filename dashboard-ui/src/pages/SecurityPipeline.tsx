import { useState } from "react";
import { Workflow, Zap, CheckCircle, RefreshCw, Activity, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "pipeline" | "cycles" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "pipeline", label: "Pipeline" }, { id: "cycles", label: "Cycles" }, { id: "metrics", label: "Metrics" }];
export default function SecurityPipeline() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Security Pipeline" subtitle="Autonomous loop: discover → pentest → find → fix → verify → repeat" icon={<Workflow className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Pipeline Cycles" value="47" icon={<RefreshCw className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Agents Dispatched" value="312" icon={<Zap className="h-5 w-5" />} />
      <MetricCard title="Findings Resolved" value="189" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Active Now" value="8 agents" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Autonomous Security Loop</h3><div className="space-y-2">
      {[{ phase: "1. Discovery", agents: "exposure_management, attack_surface", status: "completed", findings: 47 },
        { phase: "2. Pentest", agents: "network_pentest, web_app_scanner, cloud_pentest", status: "running", findings: 89 },
        { phase: "3. Analysis", agents: "finding_correlator, risk_prioritizer", status: "pending", findings: 0 },
        { phase: "4. Remediation", agents: "patch_orchestrator, config_remediation", status: "pending", findings: 0 },
        { phase: "5. Verification", agents: "remediation_verifier", status: "pending", findings: 0 },
      ].map((p, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between"><div className="flex items-center gap-3"><span className="text-cyan-400 font-mono w-6">{i + 1}.</span><div><p className="text-white/90 font-medium">{p.phase}</p><p className="text-xs text-white/40">{p.agents}</p></div></div><div className="flex items-center gap-3"><span className="text-white/50 text-sm">{p.findings} findings</span><StatusBadge status={p.status} /></div></div>))}</div></div>)}
    {tab === "pipeline" && (<div className="card-surface p-6"><h3 className="section-heading">Current Pipeline Run</h3><p className="text-sm text-white/60 mb-4">Cycle #47 — started 2 hours ago</p><div className="space-y-2">
      {[{ step: "Discover external attack surface", agent: "exposure_management", time: "12 min", status: "completed" },
        { step: "Scan network for open ports", agent: "network_pentest", time: "45 min", status: "completed" },
        { step: "Test web applications (OWASP)", agent: "web_app_scanner", time: "Running", status: "running" },
        { step: "Audit cloud IAM + storage", agent: "cloud_pentest", time: "Pending", status: "pending" },
        { step: "Correlate + deduplicate findings", agent: "finding_correlator", time: "Pending", status: "pending" },
        { step: "Prioritize by business risk", agent: "risk_prioritizer", time: "Pending", status: "pending" },
        { step: "Auto-remediate trivial fixes", agent: "vulnerability_remediation", time: "Pending", status: "pending" },
        { step: "Create tickets for complex fixes", agent: "auto_ticket_manager", time: "Pending", status: "pending" },
        { step: "Verify all fixes worked", agent: "remediation_verifier", time: "Pending", status: "pending" },
      ].map((s, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between"><div><p className="text-white/90 text-sm">{s.step}</p><p className="text-xs text-white/40">{s.agent}</p></div><div className="flex items-center gap-2"><span className="text-white/50 text-xs">{s.time}</span><StatusBadge status={s.status} /></div></div>))}</div></div>)}
    {tab === "cycles" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Cycle</th><th className="px-4 py-3">Findings</th><th className="px-4 py-3">Fixed</th><th className="px-4 py-3">Duration</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { cycle: "#47", findings: 89, fixed: 0, duration: "Running", status: "running" },
        { cycle: "#46", findings: 67, fixed: 52, duration: "3.2h", status: "completed" },
        { cycle: "#45", findings: 45, fixed: 41, duration: "2.8h", status: "completed" },
        { cycle: "#44", findings: 78, fixed: 71, duration: "4.1h", status: "completed" },
      ].map((c, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{c.cycle}</td><td className="px-4 py-3 text-white/80">{c.findings}</td><td className="px-4 py-3 text-emerald-400">{c.fixed}</td><td className="px-4 py-3 text-white/60">{c.duration}</td><td className="px-4 py-3"><StatusBadge status={c.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Pipeline Metrics</h3>
      {[{ metric: "Avg Cycle Time", value: "3.4 hours", trend: "-18% vs last month" },
        { metric: "Finding Resolution Rate", value: "91.2%", trend: "+4% vs last month" },
        { metric: "Auto-Remediation Rate", value: "61%", trend: "+8% vs last month" },
        { metric: "Verification Pass Rate", value: "94%", trend: "Stable" },
        { metric: "Agents Utilized", value: "24/168", trend: "14.3% fleet active" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">{m.trend}</p></div><span className="text-cyan-400 font-mono text-lg">{m.value}</span></div>))}</div>)}
  </div>);
}
