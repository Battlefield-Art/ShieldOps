import { useState } from "react";
import { Flame, Shield, CheckCircle, Play, RotateCcw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "experiments" | "safety" | "results";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "experiments", label: "Experiments" }, { id: "safety", label: "Safety Gates" }, { id: "results", label: "Results" }];
export default function ChaosEngineering() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Chaos Engineering" subtitle="Controlled fault injection for resilience testing" icon={<Flame className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Experiments (30d)" value="18" icon={<Play className="h-5 w-5" />} />
      <MetricCard title="Hypotheses Confirmed" value="14" icon={<CheckCircle className="h-5 w-5" />} />
      <MetricCard title="Rollbacks Triggered" value="2" icon={<RotateCcw className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Resilience Score" value="84%" icon={<Shield className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Resilience by Fault Type</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[{ type: "Pod Kill", score: 92, tests: 6 }, { type: "Network Latency", score: 78, tests: 4 }, { type: "CPU Stress", score: 85, tests: 3 }, { type: "Memory Pressure", score: 71, tests: 3 }, { type: "DNS Failure", score: 88, tests: 2 }].map((f) => (
          <div key={f.type} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><span className="text-sm text-white/60">{f.type}</span><span className={clsx("font-bold", f.score >= 85 ? "text-emerald-400" : f.score >= 75 ? "text-yellow-400" : "text-red-400")}>{f.score}%</span></div>
          <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${f.score}%` }} /></div><p className="text-xs text-white/40 mt-1">{f.tests} tests</p></div>))}
      </div></div>)}
    {tab === "experiments" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Experiment</th><th className="px-4 py-3">Fault</th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Hypothesis</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "API pod resilience", fault: "Pod Kill", target: "api-gateway", hyp: "Service recovers within 30s", status: "completed" },
        { name: "DB latency tolerance", fault: "Network Latency", target: "rds-primary", hyp: "App degrades gracefully at 200ms", status: "completed" },
        { name: "Worker memory limits", fault: "Memory Pressure", target: "worker-pool", hyp: "OOM killer triggers clean restart", status: "rolled_back" },
      ].map((e, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{e.name}</td><td className="px-4 py-3 text-white/70">{e.fault}</td><td className="px-4 py-3 font-mono text-xs text-cyan-400">{e.target}</td><td className="px-4 py-3 text-white/60 text-xs">{e.hyp}</td><td className="px-4 py-3"><StatusBadge status={e.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "safety" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Safety Gate Status</h3>
      {[{ gate: "Pre-Check (health verification)", pass: 18, fail: 0 }, { gate: "SLO Guard (abort on breach)", pass: 16, fail: 2 }, { gate: "Blast Radius (single-pod limit)", pass: 18, fail: 0 }, { gate: "Rollback Ready (verify rollback)", pass: 17, fail: 1 }].map((g) => (
        <div key={g.gate} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{g.gate}</p><p className="text-xs text-white/50">{g.pass} passed | {g.fail} failed</p></div><StatusBadge status={g.fail > 0 ? "warning" : "active"} /></div>))}</div>)}
    {tab === "results" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Experiment Outcomes (30d)</h3>
      <div className="grid grid-cols-2 gap-4">
        {[{ m: "Hypothesis Confirmed", v: "14/18 (78%)" }, { m: "Avg Recovery Time", v: "22s" }, { m: "Rollbacks Triggered", v: "2 (11%)" }, { m: "Bugs Found", v: "6" }].map((r) => (
          <div key={r.m} className="card-interactive p-4"><p className="text-sm text-white/60">{r.m}</p><p className="text-2xl font-bold text-white mt-1">{r.v}</p></div>))}
      </div></div>)}
  </div>);
}
