import { useState } from "react";
import { Activity, AlertTriangle, Network, Radio, Shield, Wifi } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "anomalies" | "protocols" | "threats";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "anomalies", label: "Anomalies" }, { id: "protocols", label: "Protocols" }, { id: "threats", label: "Threats" }];
export default function NetworkTrafficAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Network Traffic Analyzer" subtitle="Real-time flow analysis — anomaly detection, protocol inspection, threat classification" icon={<Activity className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Flows Analyzed (24h)" value="3.2M" icon={<Wifi className="h-5 w-5" />} />
      <MetricCard title="Anomalies Detected" value="89" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Protocols Tracked" value="8" icon={<Network className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Threat Score" value="72/100" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Analysis Capabilities</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Flow Ingestion", value: "NetFlow v9, IPFIX, sFlow, pcap", icon: <Radio className="h-4 w-4 text-cyan-400" /> },
        { label: "Anomaly Detection", value: "Lateral movement, C2, exfiltration, beaconing", icon: <AlertTriangle className="h-4 w-4 text-red-400" /> },
        { label: "Threat Classification", value: "Kill chain mapping + MITRE ATT&CK", icon: <Shield className="h-4 w-4 text-emerald-400" /> }].map((c) => (
        <div key={c.label} className="card-interactive p-4"><div className="flex items-center gap-2 mb-2">{c.icon}<p className="text-sm text-white/60">{c.label}</p></div><p className="font-bold text-white/90">{c.value}</p></div>))}</div></div>)}
    {tab === "anomalies" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source IP</th><th className="px-4 py-3">Destination IP</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Confidence</th><th className="px-4 py-3">Severity</th><th className="px-4 py-3">MITRE</th></tr></thead>
      <tbody>{[
        { src: "10.0.1.45", dst: "185.220.101.34", type: "C2 Beacon", confidence: "92%", severity: "critical", mitre: "T1071.001" },
        { src: "10.0.2.12", dst: "10.0.5.80", type: "Lateral Movement", confidence: "87%", severity: "high", mitre: "T1021.002" },
        { src: "10.0.3.88", dst: "45.33.32.156", type: "Data Exfiltration", confidence: "78%", severity: "high", mitre: "T1048" },
        { src: "10.0.1.22", dst: "8.8.8.8", type: "DNS Tunneling", confidence: "95%", severity: "medium", mitre: "T1071.004" },
        { src: "10.0.4.10", dst: "10.0.0.0/24", type: "Port Scan", confidence: "99%", severity: "low", mitre: "T1046" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-xs text-white/70">{a.src}</td><td className="px-4 py-3 font-mono text-xs text-white/70">{a.dst}</td><td className="px-4 py-3 text-cyan-400">{a.type}</td><td className="px-4 py-3 text-white/60">{a.confidence}</td><td className="px-4 py-3"><StatusBadge status={a.severity} /></td><td className="px-4 py-3 text-xs text-white/50">{a.mitre}</td></tr>))}</tbody></table></div>)}
    {tab === "protocols" && (<div className="space-y-3">
      {[{ protocol: "TCP", flows: "1.8M", bytes: "4.2 TB", anomalous: 34, topTalker: "10.0.1.45" },
        { protocol: "UDP", flows: "890K", bytes: "1.1 TB", anomalous: 12, topTalker: "10.0.2.12" },
        { protocol: "HTTP", flows: "520K", bytes: "890 GB", anomalous: 18, topTalker: "10.0.3.5" },
        { protocol: "DNS", flows: "340K", bytes: "42 GB", anomalous: 8, topTalker: "10.0.1.88" },
        { protocol: "TLS", flows: "410K", bytes: "1.8 TB", anomalous: 15, topTalker: "10.0.4.10" },
        { protocol: "SSH", flows: "45K", bytes: "12 GB", anomalous: 2, topTalker: "10.0.5.22" },
      ].map((p) => (<div key={p.protocol} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-sm text-cyan-400">{p.protocol}</span><StatusBadge status={p.anomalous > 15 ? "high" : p.anomalous > 5 ? "medium" : "low"} /></div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-white/50"><span>Flows: {p.flows}</span><span>Volume: {p.bytes}</span><span>Anomalous: {p.anomalous}</span><span>Top: {p.topTalker}</span></div></div>))}</div>)}
    {tab === "threats" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Classified Threats</h3>
      {[{ name: "Cobalt Strike Beacon", type: "c2_beacon", severity: "critical", phase: "Command & Control", action: "Block egress + isolate host", evidence: 4 },
        { name: "SMB Lateral Spread", type: "lateral_movement", severity: "high", phase: "Lateral Movement", action: "Disable SMB + segment network", evidence: 7 },
        { name: "DNS Exfiltration", type: "data_exfiltration", severity: "high", phase: "Exfiltration", action: "Block DNS to external resolvers", evidence: 3 },
        { name: "Internal Recon", type: "port_scan", severity: "medium", phase: "Discovery", action: "Monitor + rate limit", evidence: 12 },
      ].map((t, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{t.name}</p><p className="text-xs text-white/50">Phase: {t.phase} | Evidence: {t.evidence} flows</p><p className="text-xs text-cyan-400 mt-1">Action: {t.action}</p></div><StatusBadge status={t.severity} /></div>))}</div>)}
  </div>);
}
