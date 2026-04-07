import { useState } from "react";
import { Crosshair, Shield, AlertTriangle, Target, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "campaign" | "phases" | "results";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "campaign", label: "Campaign" }, { id: "phases", label: "Kill Chain" }, { id: "results", label: "Results" }];
export default function APTEmulator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="APT Emulator" subtitle="Simulate full APT campaigns — recon through exfiltration (safe only)" icon={<Crosshair className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Campaigns Run" value="8" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Phases Blocked" value="67%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Phases Evaded" value="12%" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Overall Score" value="78/100" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Campaign Results</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ result: "Blocked", count: "67%", color: "text-emerald-400" }, { result: "Detected", count: "21%", color: "text-cyan-400" }, { result: "Partial", count: "8%", color: "text-yellow-400" }, { result: "Evaded", count: "4%", color: "text-red-400" }].map((r) => (
        <div key={r.result} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{r.result}</p><p className={clsx("text-3xl font-bold mt-1", r.color)}>{r.count}</p></div>))}</div></div>)}
    {tab === "campaign" && (<div className="space-y-3">
      {[{ id: "APT-008", group: "Simulated APT29", type: "Credential theft + cloud pivot", phases: 7, blocked: 5, status: "completed" },
        { id: "APT-007", group: "Simulated Lazarus", type: "Supply chain + ransomware", phases: 6, blocked: 4, status: "completed" },
        { id: "APT-006", group: "Simulated APT28", type: "Phishing + lateral movement", phases: 5, blocked: 4, status: "completed" },
      ].map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="text-xs text-white/40 ml-2">{c.group}</span></div><StatusBadge status={c.status} /></div>
        <p className="text-white/90 font-medium">{c.type}</p><p className="text-xs text-white/50">{c.phases} phases | {c.blocked} blocked</p></div>))}</div>)}
    {tab === "phases" && (<div className="card-surface p-6"><h3 className="section-heading">Kill Chain Results (Latest)</h3><div className="space-y-2">
      {[{ phase: "1. Recon", technique: "OSINT + DNS enum", result: "detected" },
        { phase: "2. Initial Access", technique: "Phishing simulation", result: "blocked" },
        { phase: "3. Execution", technique: "PowerShell obfuscation", result: "detected" },
        { phase: "4. Persistence", technique: "Scheduled task", result: "blocked" },
        { phase: "5. Lateral Movement", technique: "SMB + WMI", result: "partially_detected" },
        { phase: "6. Collection", technique: "Archive staging", result: "detected" },
        { phase: "7. Exfiltration", technique: "DNS tunneling", result: "evaded" },
      ].map((p, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between"><div><span className="text-cyan-400 font-mono text-sm w-24">{p.phase}</span><span className="text-white/70 text-sm ml-2">{p.technique}</span></div><StatusBadge status={p.result} /></div>))}</div></div>)}
    {tab === "results" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Defense Effectiveness</h3>
      {[{ area: "Email gateway blocked phishing", score: "95%", status: "excellent" },
        { area: "EDR detected PowerShell abuse", score: "88%", status: "good" },
        { area: "Network monitoring caught lateral", score: "72%", status: "adequate" },
        { area: "DNS exfil detection", score: "23%", status: "insufficient" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.area}</p><p className="text-xs text-white/50">{r.score}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
