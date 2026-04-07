import { useState } from "react";
import { Search, Crosshair, Database, AlertTriangle, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "hypotheses" | "findings" | "backups";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "hypotheses", label: "Hypotheses" }, { id: "findings", label: "Findings" }, { id: "backups", label: "Backup Scans" }];
export default function DataThreatHunting() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Data Threat Hunting" subtitle="LLM-powered threat hunting across production, backups, and AI pipelines" icon={<Search className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Hunts" value="5" icon={<Crosshair className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Threats Found (7d)" value="8" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Backups Scanned" value="234" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Hunt Accuracy" value="94%" icon={<Target className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Hunt Sources</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ src: "Production", hunts: 3, threats: 4, color: "text-cyan-400" }, { src: "Backup Snapshots", hunts: 1, threats: 3, color: "text-yellow-400" }, { src: "AI Pipelines", hunts: 1, threats: 1, color: "text-red-400" }].map((s) => (
        <div key={s.src} className="card-interactive p-4"><p className={clsx("font-bold", s.color)}>{s.src}</p><p className="text-white/50 text-xs mt-1">{s.hunts} active hunts | {s.threats} threats found</p></div>))}</div></div>)}
    {tab === "hypotheses" && (<div className="space-y-3">
      {[{ id: "HYP-005", hypothesis: "Ransomware staging in backup snapshots older than 30d", mitre: "T1486", source: "backup_snapshot", status: "hunting" },
        { id: "HYP-004", hypothesis: "Credential harvesting via AI prompt injection", mitre: "T1557", source: "ai_pipeline", status: "confirmed" },
        { id: "HYP-003", hypothesis: "Lateral movement persistence in system images", mitre: "T1547", source: "production", status: "hunting" },
      ].map((h) => (<div key={h.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{h.id}</span><span className="text-xs text-white/40 ml-2">{h.mitre}</span></div><StatusBadge status={h.status} /></div>
        <p className="text-white/90 font-medium">{h.hypothesis}</p><p className="text-xs text-white/50">Source: {h.source}</p></div>))}</div>)}
    {tab === "findings" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Confirmed Threats</h3>
      {[{ finding: "LockBit staging files in 45-day-old backup", source: "Backup snapshot", severity: "critical", evidence: "Encrypted test files, ransom note template" },
        { finding: "Cobalt Strike beacon in system image", source: "Production", severity: "critical", evidence: "DNS-over-HTTPS C2, process injection" },
        { finding: "PII exfiltration via RAG pipeline", source: "AI Pipeline", severity: "high", evidence: "Customer SSNs in embedding vectors" },
      ].map((f, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{f.finding}</p><StatusBadge status={f.severity} /></div>
        <p className="text-xs text-white/50">Source: {f.source} | Evidence: {f.evidence}</p></div>))}</div>)}
    {tab === "backups" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Snapshot</th><th className="px-4 py-3">Age</th><th className="px-4 py-3">Scanned</th><th className="px-4 py-3">Threats</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { snap: "prod-db-daily-45d", age: "45 days", scanned: "2h ago", threats: 1, status: "infected" },
        { snap: "prod-db-daily-30d", age: "30 days", scanned: "2h ago", threats: 0, status: "clean" },
        { snap: "k8s-weekly-14d", age: "14 days", scanned: "4h ago", threats: 0, status: "clean" },
        { snap: "file-srv-daily-7d", age: "7 days", scanned: "1h ago", threats: 0, status: "clean" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-xs text-white/70">{s.snap}</td><td className="px-4 py-3 text-white/60">{s.age}</td><td className="px-4 py-3 text-white/50">{s.scanned}</td><td className="px-4 py-3"><span className={s.threats > 0 ? "text-red-400" : "text-emerald-400"}>{s.threats}</span></td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
  </div>);
}
