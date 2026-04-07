import { useState } from "react";
import { GitBranch, Shield, AlertTriangle, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "pipeline_scans" | "gate_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "pipeline_scans", label: "Pipeline Scans" },
  { id: "gate_status", label: "Gate Status" },
  { id: "metrics", label: "Metrics" },
];

const PIPELINES = [
  { name: "frontend-deploy", provider: "GitHub Actions", gates: 5, status: "healthy", detail: "All 5 gates passed, last run 12m ago" },
  { name: "api-service-ci", provider: "GitHub Actions", gates: 6, status: "critical", detail: "SAST gate failed: 2 critical SQL injection findings" },
  { name: "infra-terraform", provider: "GitLab CI", gates: 4, status: "warning", detail: "IaC scan: 3 medium-severity misconfigurations" },
  { name: "mobile-app-build", provider: "CircleCI", gates: 3, status: "healthy", detail: "SCA clean, no vulnerable dependencies" },
  { name: "data-pipeline", provider: "GitHub Actions", gates: 4, status: "warning", detail: "Secret scan: 1 potential API key in config" },
];

export default function SecurityAutomationPipeline() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Automation Pipeline" subtitle="CI/CD security gate integration, SAST/DAST/SCA pipeline checks" icon={<GitBranch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Pipelines Monitored" value="47" icon={<GitBranch className="h-5 w-5" />} />
        <MetricCard title="Gates Active" value="214" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Findings Today" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Deployments Blocked" value="4" icon={<Lock className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Gate Pass Rate</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "SAST", v: "89%", c: "text-emerald-400" }, { l: "SCA", v: "94%", c: "text-emerald-400" }, { l: "Secret Scan", v: "97%", c: "text-emerald-400" }, { l: "Container", v: "82%", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "pipeline_scans" && (<div className="space-y-3">{PIPELINES.map((p) => (<div key={p.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{p.name}</span><span className="ml-2 text-xs text-white/40">{p.provider}</span></div><StatusBadge status={p.status} /></div><p className="text-white/50 text-sm">{p.detail}</p><span className="text-xs text-white/40">{p.gates} security gates</span></div>))}</div>)}
      {tab === "gate_status" && (<div className="card-surface p-6"><h3 className="section-heading">Recent Gate Decisions</h3><div className="space-y-2">{[{ pipeline: "api-service-ci", gate: "SAST", decision: "BLOCKED", severity: "critical" }, { pipeline: "data-pipeline", gate: "Secret Scan", decision: "WARNING", severity: "warning" }, { pipeline: "infra-terraform", gate: "IaC Scan", decision: "WARNING", severity: "warning" }, { pipeline: "frontend-deploy", gate: "SCA", decision: "PASSED", severity: "healthy" }].map((g, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div className="flex gap-2"><span className="text-white/70 font-mono">{g.pipeline}</span><span className="text-white/40">{g.gate}</span></div><div className="flex gap-3 items-center"><span className="text-white/50">{g.decision}</span><StatusBadge status={g.severity} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Pipeline Security Trends</h3>{[{ m: "Avg Gate Duration", v: "18s", t: "-3s vs last week" }, { m: "Block Rate", v: "8.5%", t: "-2.1%" }, { m: "Fix Time (Critical)", v: "2.4h", t: "-0.8h" }, { m: "Coverage Score", v: "91%", t: "+3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
