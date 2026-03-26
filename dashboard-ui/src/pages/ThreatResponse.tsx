import { useState } from "react";
import { Zap, Shield, AlertTriangle, Target, CheckCircle, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "threats" | "playbooks" | "actions";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "threats", label: "Active Threats" }, { id: "playbooks", label: "Playbooks" }, { id: "actions", label: "Response Actions" }];
export default function ThreatResponse() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Threat Response" subtitle="Automated threat response playbook orchestration" icon={<Zap className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Threats" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Playbooks Available" value="12" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Auto-Contained (7d)" value="8" icon={<Shield className="h-5 w-5" />} />
      <MetricCard title="Avg Response Time" value="2.4 min" icon={<Clock className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Response Summary (7d)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Contained", count: 8, color: "text-emerald-400" }, { label: "Eradicated", count: 6, color: "text-cyan-400" }, { label: "In Progress", count: 3, color: "text-yellow-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "threats" && (<div className="space-y-3">
      {[{ id: "THR-001", type: "Credential Compromise", tactic: "Initial Access", indicators: 4, status: "containing", sev: "critical" },
        { id: "THR-002", type: "Malware Execution", tactic: "Execution", indicators: 2, status: "eradicating", sev: "high" },
        { id: "THR-003", type: "Data Exfiltration Attempt", tactic: "Exfiltration", indicators: 3, status: "contained", sev: "critical" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.tactic}</span></div><StatusBadge status={t.sev} /></div>
        <p className="text-white/90 font-medium">{t.type}</p><p className="text-xs text-white/50">{t.indicators} indicators | <StatusBadge status={t.status} /></p></div>))}</div>)}
    {tab === "playbooks" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Playbook</th><th className="px-4 py-3">Threat Types</th><th className="px-4 py-3">Steps</th><th className="px-4 py-3">Auto</th><th className="px-4 py-3">Avg Time</th></tr></thead>
      <tbody>{[
        { name: "Credential Compromise", types: "T1078, T1110", steps: 6, auto: true, time: "3.2 min" },
        { name: "Malware Containment", types: "T1204, T1059", steps: 8, auto: true, time: "4.5 min" },
        { name: "Data Exfiltration", types: "T1041, T1048", steps: 5, auto: false, time: "8.1 min" },
        { name: "Ransomware Response", types: "T1486", steps: 10, auto: false, time: "15 min" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{p.name}</td><td className="px-4 py-3 font-mono text-xs text-white/60">{p.types}</td><td className="px-4 py-3 text-white/80">{p.steps}</td><td className="px-4 py-3">{p.auto ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <span className="text-white/40">Manual</span>}</td><td className="px-4 py-3 text-white/70">{p.time}</td></tr>))}</tbody></table></div>)}
    {tab === "actions" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Response Actions</h3>
      {[{ action: "Credential Revocation", target: "svc-admin@aws", playbook: "Credential Compromise", status: "completed", time: "1.2 min" },
        { action: "Network Isolation", target: "worker-pod-xyz", playbook: "Malware Containment", status: "completed", time: "0.8 min" },
        { action: "Data Flow Block", target: "s3-export-bucket", playbook: "Data Exfiltration", status: "in_progress", time: "—" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.action}</p><p className="text-xs text-white/50">{a.playbook} | Target: {a.target} | {a.time}</p></div><StatusBadge status={a.status} /></div>))}</div>)}
  </div>);
}
