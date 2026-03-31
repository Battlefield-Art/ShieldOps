import { useState } from "react";
import { TestTube2, Shield, AlertTriangle, Target, Activity, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "sandbox_instances" | "test_results" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "sandbox_instances", label: "Sandbox Instances" },
  { id: "test_results", label: "Test Results" },
  { id: "metrics", label: "Metrics" },
];

const INSTANCES = [
  { id: "SBX-001", name: "Ransomware Detonation Lab", type: "Malware Detonation", status: "running", scenarios: 8, isolation: "Full" },
  { id: "SBX-002", name: "APT Simulation Env", type: "Attack Simulation", status: "running", scenarios: 12, isolation: "Full" },
  { id: "SBX-003", name: "Config Hardening Test", type: "Config Testing", status: "completed", scenarios: 5, isolation: "Network" },
  { id: "SBX-004", name: "Red Team Exercise Q1", type: "Red Team", status: "provisioning", scenarios: 15, isolation: "Full" },
];

const RESULTS = [
  { id: "TST-001", sandbox: "SBX-001", scenario: "WannaCry variant detonation", outcome: "detected", detectionMs: 340, severity: "critical" },
  { id: "TST-002", sandbox: "SBX-002", scenario: "Cobalt Strike beacon callback", outcome: "evaded", detectionMs: 0, severity: "high" },
  { id: "TST-003", sandbox: "SBX-002", scenario: "Kerberoasting attempt", outcome: "detected", detectionMs: 1200, severity: "high" },
  { id: "TST-004", sandbox: "SBX-003", scenario: "SSH key with weak cipher", outcome: "detected", detectionMs: 50, severity: "medium" },
];

export default function SecuritySimulationSandbox() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Simulation Sandbox" subtitle="Isolated security testing and attack simulation environments" icon={<TestTube2 className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Sandboxes" value="3" icon={<TestTube2 className="h-5 w-5" />} />
        <MetricCard title="Tests Executed (30d)" value="156" icon={<Target className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Detection Coverage" value="87%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Evasion Rate" value="13%" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Sandbox Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Malware Detonation", v: "23", c: "text-red-400" }, { l: "Attack Simulation", v: "45", c: "text-cyan-400" }, { l: "Config Testing", v: "18", c: "text-emerald-400" }, { l: "Red Team", v: "12", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "sandbox_instances" && (<div className="space-y-3">{INSTANCES.map((inst) => (<div key={inst.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{inst.id}</span><span className="ml-2 text-xs text-white/40">{inst.type}</span></div><StatusBadge status={inst.status} /></div><p className="text-white/90 text-sm font-medium">{inst.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{inst.scenarios} scenarios</span><span>Isolation: {inst.isolation}</span></div></div>))}</div>)}
      {tab === "test_results" && (<div className="space-y-3">{RESULTS.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.sandbox}</span></div><StatusBadge status={r.outcome === "detected" ? "success" : "error"} /></div><p className="text-white/90 text-sm">{r.scenario}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className={r.outcome === "evaded" ? "text-red-400" : "text-emerald-400"}>{r.outcome}</span>{r.detectionMs > 0 && <span>Detection: {r.detectionMs}ms</span>}<StatusBadge status={r.severity} /></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Testing Performance</h3>{[{ m: "Detection Coverage", v: "87%", t: "+4%" }, { m: "Avg Detection Time", v: "420ms", t: "-80ms" }, { m: "Evasion Rate", v: "13%", t: "-4%" }, { m: "Tests per Week", v: "39", t: "+7" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
