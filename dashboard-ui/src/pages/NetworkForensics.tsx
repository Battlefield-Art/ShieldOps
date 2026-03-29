import { useState } from "react";
import { FileSearch, Network, Clock, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "sessions" | "timeline" | "exfiltration";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "sessions", label: "Sessions" }, { id: "timeline", label: "Timeline" }, { id: "exfiltration", label: "Exfiltration" }];
export default function NetworkForensics() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Network Forensics" subtitle="Pcap analysis, session reconstruction, lateral movement tracing" icon={<FileSearch className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Sessions Analyzed" value="4,892" icon={<Network className="h-5 w-5" />} />
      <MetricCard title="Lateral Hops" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Exfil Paths" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Analysis Time" value="4.2 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Protocol Distribution</h3><div className="grid grid-cols-2 md:grid-cols-4 gap-3">{[{ proto: "HTTPS", count: 2341, color: "text-emerald-400" }, { proto: "DNS", count: 1203, color: "text-cyan-400" }, { proto: "SMB", count: 456, color: "text-yellow-400" }, { proto: "SSH", count: 234, color: "text-white/60" }].map((p) => (<div key={p.proto} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{p.proto}</p><p className={clsx("text-xl font-bold mt-1", p.color)}>{p.count}</p></div>))}</div></div>)}
    {tab === "sessions" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Destination</th><th className="px-4 py-3">Protocol</th><th className="px-4 py-3">Bytes</th><th className="px-4 py-3">Risk</th></tr></thead><tbody>{[{ src: "10.0.1.45", dst: "203.0.113.50", proto: "HTTPS", bytes: "2.3 MB", risk: "high" }, { src: "10.0.1.45", dst: "10.0.2.12", proto: "SMB", bytes: "450 KB", risk: "medium" }].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{s.src}</td><td className="px-4 py-3 text-white/80">{s.dst}</td><td className="px-4 py-3 text-white/70">{s.proto}</td><td className="px-4 py-3 text-white/60">{s.bytes}</td><td className="px-4 py-3"><StatusBadge status={s.risk} /></td></tr>))}</tbody></table></div>)}
    {tab === "timeline" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Forensic Timeline</h3>{[{ time: "14:23:01", event: "Initial C2 beacon to 203.0.113.50:443", severity: "critical" }, { time: "14:25:12", event: "Lateral movement via SMB to 10.0.2.12", severity: "high" }, { time: "14:28:45", event: "Data staging detected on 10.0.2.12", severity: "high" }, { time: "14:31:00", event: "Exfiltration via HTTPS to 198.51.100.23", severity: "critical" }].map((e, i) => (<div key={i} className="card-interactive p-3 flex items-center gap-4"><span className="text-cyan-400 font-mono text-xs w-16">{e.time}</span><div><p className="text-white/80 text-sm">{e.event}</p></div><StatusBadge status={e.severity} /></div>))}</div>)}
    {tab === "exfiltration" && (<div className="space-y-3">{[{ src: "10.0.1.45", dst: "203.0.113.50", method: "HTTPS bulk transfer", bytes: "2.3 MB", confidence: "92%" }, { src: "10.0.2.12", dst: "198.51.100.23", method: "DNS tunneling", bytes: "450 KB", confidence: "87%" }].map((e, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{e.method}</p><p className="text-xs text-white/50">{e.src} → {e.dst} | {e.bytes} | Confidence: {e.confidence}</p></div>))}</div>)}
  </div>);
}
