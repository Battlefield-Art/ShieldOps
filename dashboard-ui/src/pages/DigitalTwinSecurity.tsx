import { useState } from "react";
import { Boxes, Play, AlertTriangle, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "twins" | "simulations" | "results";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "twins", label: "Digital Twins" }, { id: "simulations", label: "Simulations" }, { id: "results", label: "Results" }];
export default function DigitalTwinSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Digital Twin Security" subtitle="Security posture simulation and pre-deployment testing" icon={<Boxes className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Twins" value="8" icon={<Boxes className="h-5 w-5" />} />
      <MetricCard title="Simulations Run (7d)" value="34" icon={<Play className="h-5 w-5" />} />
      <MetricCard title="Vulnerabilities Found" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Posture Score" value="B+" icon={<BarChart3 className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Simulation Summary (7d)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ label: "Passed", count: 22, color: "text-emerald-400" }, { label: "Failed", count: 8, color: "text-red-400" }, { label: "Partial", count: 3, color: "text-yellow-400" }, { label: "Inconclusive", count: 1, color: "text-white/40" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "twins" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Twin</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Fidelity</th><th className="px-4 py-3">Last Sync</th><th className="px-4 py-3">Posture</th></tr></thead>
      <tbody>{[
        { name: "prod-k8s-cluster", type: "Infrastructure", fidelity: "High", sync: "5 min ago", posture: "adequate" },
        { name: "api-gateway-twin", type: "Application", fidelity: "High", sync: "12 min ago", posture: "hardened" },
        { name: "identity-fabric", type: "Identity", fidelity: "Medium", sync: "1h ago", posture: "vulnerable" },
        { name: "dmz-network", type: "Network", fidelity: "High", sync: "30 min ago", posture: "adequate" },
      ].map((t, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{t.name}</td><td className="px-4 py-3 text-white/60">{t.type}</td><td className="px-4 py-3 text-white/70">{t.fidelity}</td><td className="px-4 py-3 text-white/50">{t.sync}</td><td className="px-4 py-3"><StatusBadge status={t.posture} /></td></tr>))}</tbody></table></div>)}
    {tab === "simulations" && (<div className="space-y-3">
      {[{ id: "SIM-034", twin: "prod-k8s-cluster", scenario: "Lateral Movement via Service Account", type: "lateral_movement", status: "completed", outcome: "failed" },
        { id: "SIM-033", twin: "api-gateway-twin", scenario: "API Rate Limit Bypass", type: "application", status: "completed", outcome: "passed" },
        { id: "SIM-032", twin: "identity-fabric", scenario: "Privilege Escalation Chain", type: "identity", status: "completed", outcome: "failed" },
        { id: "SIM-031", twin: "dmz-network", scenario: "Ransomware Propagation", type: "ransomware_spread", status: "running", outcome: "partial" },
      ].map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="text-xs text-white/40 ml-2">{s.twin}</span></div><StatusBadge status={s.outcome} /></div>
        <p className="text-white/90 font-medium">{s.scenario}</p><p className="text-xs text-white/50">Type: {s.type} | <StatusBadge status={s.status} /></p></div>))}</div>)}
    {tab === "results" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Posture Assessment Results</h3>
      {[{ category: "Network Segmentation", grade: "A", findings: 1, status: "hardened" },
        { category: "Identity Security", grade: "C", findings: 5, status: "vulnerable" },
        { category: "Application Security", grade: "A", findings: 0, status: "hardened" },
        { category: "Data Protection", grade: "B", findings: 3, status: "adequate" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div className="flex items-center gap-4"><span className={clsx("text-2xl font-bold", r.grade === "A" ? "text-emerald-400" : r.grade === "B" ? "text-cyan-400" : "text-yellow-400")}>{r.grade}</span><div><p className="text-white/90 font-medium">{r.category}</p><p className="text-xs text-white/50">{r.findings} findings</p></div></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
