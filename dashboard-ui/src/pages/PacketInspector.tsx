import { useState } from "react";
import { Network, Shield, Lock, AlertTriangle, Activity, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "payloads" | "tls" | "threats";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "payloads", label: "Payloads" }, { id: "tls", label: "TLS Certs" }, { id: "threats", label: "Threats" }];
export default function PacketInspector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Packet Inspector" subtitle="Deep packet inspection — protocol decoding, payload analysis, TLS validation, threat detection" icon={<Network className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Packets Inspected (24h)" value="1.4M" icon={<Eye className="h-5 w-5" />} />
      <MetricCard title="Threats Detected" value="47" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="TLS Valid Rate" value="96.2%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Avg Entropy" value="5.41" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Inspection Capabilities</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Protocol Decoding", value: "HTTP, DNS, TLS, SSH, SMTP, DB", icon: <Network className="h-4 w-4 text-cyan-400" /> },
        { label: "Payload Analysis", value: "Pattern matching + LLM reasoning", icon: <Shield className="h-4 w-4 text-emerald-400" /> },
        { label: "TLS Validation", value: "Cert chain, cipher, JA3 fingerprint", icon: <Lock className="h-4 w-4 text-yellow-400" /> }].map((c) => (
        <div key={c.label} className="card-interactive p-4"><div className="flex items-center gap-2 mb-2">{c.icon}<p className="text-sm text-white/60">{c.label}</p></div><p className="font-bold text-white/90">{c.value}</p></div>))}</div></div>)}
    {tab === "payloads" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Destination</th><th className="px-4 py-3">Protocol</th><th className="px-4 py-3">Entropy</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Signatures</th></tr></thead>
      <tbody>{[
        { src: "10.0.1.45:52341", dst: "185.220.101.34:443", proto: "TLS", entropy: "7.83", risk: "critical", sigs: "encoded_payload, remote_download" },
        { src: "10.0.2.12:38921", dst: "93.184.216.34:80", proto: "HTTP", entropy: "4.21", risk: "high", sigs: "sql_injection" },
        { src: "10.0.1.88:41023", dst: "8.8.8.8:53", proto: "DNS", entropy: "6.91", risk: "medium", sigs: "dns_tunnel_suspect" },
        { src: "10.0.3.5:49200", dst: "172.16.0.10:3306", proto: "MySQL", entropy: "3.12", risk: "low", sigs: "none" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-xs text-white/70">{p.src}</td><td className="px-4 py-3 font-mono text-xs text-white/70">{p.dst}</td><td className="px-4 py-3 text-cyan-400">{p.proto}</td><td className="px-4 py-3 text-white/60">{p.entropy}</td><td className="px-4 py-3"><StatusBadge status={p.risk} /></td><td className="px-4 py-3 text-xs text-white/50">{p.sigs}</td></tr>))}</tbody></table></div>)}
    {tab === "tls" && (<div className="space-y-3">
      {[{ server: "api.example.com", version: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", status: "valid", issuer: "Let's Encrypt", expires: "2026-09-15" },
        { server: "legacy.internal.corp", version: "TLSv1.0", cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", status: "weak_cipher", issuer: "Self-Signed", expires: "2025-01-01" },
        { server: "payments.vendor.io", version: "TLSv1.2", cipher: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", status: "valid", issuer: "DigiCert", expires: "2026-12-01" },
        { server: "staging.app.dev", version: "TLSv1.2", cipher: "TLS_RSA_WITH_RC4_128_SHA", status: "weak_cipher", issuer: "Internal CA", expires: "2026-03-01" },
      ].map((t) => (<div key={t.server} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-sm text-cyan-400">{t.server}</span><StatusBadge status={t.status} /></div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-white/50"><span>Version: {t.version}</span><span>Issuer: {t.issuer}</span><span>Expires: {t.expires}</span><span className="font-mono">{t.cipher.slice(0, 30)}...</span></div></div>))}</div>)}
    {tab === "threats" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detected Threats</h3>
      {[{ type: "SQL Injection", src: "10.0.2.12", dst: "93.184.216.34:80", severity: "critical", mitre: "T1190", action: "Block source IP" },
        { type: "Encrypted C2", src: "10.0.1.45", dst: "185.220.101.34:443", severity: "high", mitre: "T1573", action: "TLS interception + block" },
        { type: "Weak TLS", src: "legacy.internal.corp", dst: "N/A", severity: "medium", mitre: "T1557", action: "Upgrade to TLS 1.3" },
        { type: "DNS Tunneling", src: "10.0.1.88", dst: "8.8.8.8:53", severity: "high", mitre: "T1071.004", action: "DNS filtering rule" },
        { type: "Credential Leak", src: "10.0.3.22", dst: "external.api.io:443", severity: "critical", mitre: "T1040", action: "Rotate credentials" },
      ].map((t, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{t.type}</p><p className="text-xs text-white/50">{t.src} &rarr; {t.dst} | MITRE: {t.mitre}</p><p className="text-xs text-cyan-400 mt-1">Action: {t.action}</p></div><StatusBadge status={t.severity} /></div>))}</div>)}
  </div>);
}
