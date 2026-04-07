import { useState } from "react";
import { Users, Shield, Target, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "exercises" | "scores" | "improvements";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "exercises", label: "Exercises" }, { id: "scores", label: "Scores" }, { id: "improvements", label: "Improvements" }];
export default function PurpleTeam() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Purple Team" subtitle="Coordinated red+blue exercises — attack, detect, respond, measure" icon={<Users className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Exercises Run" value="12" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Red Score" value="72/100" icon={<Shield className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Blue Score" value="81/100" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Combined" value="Good" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Red vs Blue</h3><div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div className="card-interactive p-4 text-center border-l-4 border-red-500"><p className="text-red-400 font-bold">Red Team</p><p className="text-3xl font-bold text-white/80 mt-2">72</p><p className="text-xs text-white/40">Attack effectiveness</p></div>
      <div className="card-interactive p-4 text-center border-l-4 border-cyan-500"><p className="text-cyan-400 font-bold">Blue Team</p><p className="text-3xl font-bold text-white/80 mt-2">81</p><p className="text-xs text-white/40">Defense effectiveness</p></div></div></div>)}
    {tab === "exercises" && (<div className="space-y-3">
      {[{ id: "PE-012", type: "Assumed Breach", scenario: "Attacker has valid credentials — can they escalate?", red: 68, blue: 85, verdict: "good" },
        { id: "PE-011", type: "Live Fire", scenario: "Simulated ransomware attack chain", red: 74, blue: 79, verdict: "good" },
        { id: "PE-010", type: "Tabletop", scenario: "Supply chain compromise response", red: 71, blue: 76, verdict: "adequate" },
      ].map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="text-xs text-white/40 ml-2">{e.type}</span></div><StatusBadge status={e.verdict} /></div>
        <p className="text-white/90 font-medium">{e.scenario}</p><p className="text-xs text-white/50">Red: {e.red} | Blue: {e.blue}</p></div>))}</div>)}
    {tab === "scores" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Capability</th><th className="px-4 py-3">Red</th><th className="px-4 py-3">Blue</th><th className="px-4 py-3">Gap</th></tr></thead>
      <tbody>{[
        { cap: "Initial Access", red: 78, blue: 89, gap: "+11 Blue" },
        { cap: "Lateral Movement", red: 82, blue: 71, gap: "+11 Red" },
        { cap: "Data Exfiltration", red: 75, blue: 68, gap: "+7 Red" },
        { cap: "Persistence", red: 69, blue: 84, gap: "+15 Blue" },
        { cap: "Detection Speed", red: 65, blue: 88, gap: "+23 Blue" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.cap}</td><td className="px-4 py-3 text-red-400">{s.red}</td><td className="px-4 py-3 text-cyan-400">{s.blue}</td><td className="px-4 py-3 text-white/50">{s.gap}</td></tr>))}</tbody></table></div>)}
    {tab === "improvements" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Improvement Trends (6 months)</h3>
      {[{ area: "Detection speed", before: "12 min", after: "3 min", improvement: "-75%" },
        { area: "Lateral containment", before: "45 min", after: "8 min", improvement: "-82%" },
        { area: "Exfil prevention", before: "42%", after: "68%", improvement: "+62%" },
      ].map((i, idx) => (<div key={idx} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{i.area}</p><p className="text-xs text-white/50">{i.before} → {i.after}</p></div><span className="text-emerald-400 font-mono">{i.improvement}</span></div>))}</div>)}
  </div>);
}
