import { useState } from "react";
import { Search, Brain, FileSearch, Bug, Fingerprint } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "memory" | "files" | "timeline";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "memory", label: "Memory Analysis" }, { id: "files", label: "Carved Files" }, { id: "timeline", label: "Timeline" }];
export default function EndpointForensics() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Endpoint Forensics" subtitle="Memory analysis, process investigation, file carving, and timeline reconstruction" icon={<Search className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Cases" value="3" icon={<Fingerprint className="h-5 w-5" />} />
      <MetricCard title="Artifacts Collected" value="47" icon={<FileSearch className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Malware Found" value="5" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="IOCs Extracted" value="23" icon={<Brain className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Forensics Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Memory Dumps", count: 4, color: "text-cyan-400" }, { label: "Injected Processes", count: 2, color: "text-red-400" }, { label: "Timeline Events", count: 47, color: "text-emerald-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "memory" && (<div className="space-y-3">
      {[{ id: "MEM-001", type: "Process Injection", process: "svchost.exe (PID 3248)", severity: "critical", details: "Cobalt Strike beacon injected", indicators: ["cobalt_strike_watermark", "named_pipe_c2"] },
        { id: "MEM-002", type: "Process Hollowing", process: "explorer.exe (PID 1024)", severity: "high", details: "PE header mismatch detected", indicators: ["unmapped_memory_region"] },
        { id: "MEM-003", type: "Credential Dumping", process: "lsass.exe (PID 672)", severity: "critical", details: "LSASS memory access for credential theft", indicators: ["lsass_access_handle", "minidump_creation"] },
      ].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="text-xs text-white/40 ml-2">{f.process}</span></div><StatusBadge status={f.severity} /></div>
        <p className="text-white/90 font-medium">{f.type}</p><p className="text-white/70 text-sm">{f.details}</p><div className="flex gap-2 mt-2">{f.indicators.map((ind) => (<span key={ind} className="text-xs bg-white/10 px-2 py-0.5 rounded font-mono">{ind}</span>))}</div></div>))}</div>)}
    {tab === "files" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">File</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Size</th><th className="px-4 py-3">Verdict</th><th className="px-4 py-3">Malware</th></tr></thead>
      <tbody>{[
        { name: "payload.exe", type: "PE executable", size: "245KB", verdict: "Cobalt Strike loader", malware: "critical" },
        { name: "stage2.ps1", type: "PowerShell", size: "12KB", verdict: "Obfuscated downloader", malware: "high" },
        { name: "data.7z", type: "7-Zip archive", size: "15MB", verdict: "Exfiltrated data", malware: "info" },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-mono text-xs">{f.name}</td><td className="px-4 py-3 text-white/60">{f.type}</td><td className="px-4 py-3 text-white/60">{f.size}</td><td className="px-4 py-3 text-white/80">{f.verdict}</td><td className="px-4 py-3"><StatusBadge status={f.malware} /></td></tr>))}</tbody></table></div>)}
    {tab === "timeline" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Attack Timeline</h3>
      {[{ time: "T+0:00", event: "Phishing email delivered", source: "Email", severity: "high" },
        { time: "T+0:02", event: "PowerShell encoded command executed", source: "Process", severity: "critical" },
        { time: "T+0:05", event: "Cobalt Strike C2 beacon established", source: "Network", severity: "critical" },
        { time: "T+0:15", event: "LSASS credential dumping", source: "Memory", severity: "critical" },
        { time: "T+0:30", event: "Data archived and staged for exfiltration", source: "Filesystem", severity: "high" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4 flex items-center gap-4"><div className="text-xs font-mono text-cyan-400 w-16 shrink-0">{e.time}</div><div className="flex-1"><p className="text-white/90 font-medium">{e.event}</p><p className="text-xs text-white/50">Source: {e.source}</p></div><StatusBadge status={e.severity} /></div>))}</div>)}
  </div>);
}
