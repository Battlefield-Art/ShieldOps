import { useState } from "react";
import { ShieldAlert, Eye, Database, Ban, Brain } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "flows" | "detections" | "policies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "flows", label: "Data Flows" }, { id: "detections", label: "Exfil Detections" }, { id: "policies", label: "DLP Policies" }];
export default function DataLossPrevention() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Data Loss Prevention" subtitle="Cross-surface DLP — endpoints, cloud, browsers, and AI pipelines" icon={<ShieldAlert className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Data Flows Monitored" value="2.4K" icon={<Eye className="h-5 w-5" />} />
      <MetricCard title="Sensitive Records" value="847" icon={<Database className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Exfil Blocked (7d)" value="12" icon={<Ban className="h-5 w-5 text-red-400" />} />
      <MetricCard title="AI Pipeline Leaks" value="3" icon={<Brain className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">DLP by Surface (7d)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ surface: "Endpoint", blocked: 4, monitored: 890 }, { surface: "Cloud Storage", blocked: 3, monitored: 456 }, { surface: "AI Pipeline", blocked: 3, monitored: 234 }, { surface: "Browser/Email", blocked: 2, monitored: 812 }].map((s) => (
        <div key={s.surface} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.surface}</p><p className="text-red-400 text-2xl font-bold mt-1">{s.blocked} blocked</p><p className="text-xs text-white/40">{s.monitored} monitored</p></div>))}</div></div>)}
    {tab === "flows" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Destination</th><th className="px-4 py-3">Data Type</th><th className="px-4 py-3">Sensitivity</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { src: "Customer DB", dst: "LLM Prompt", type: "PII", sens: "restricted", status: "blocked" },
        { src: "Code Repo", dst: "ChatGPT API", type: "Secrets", sens: "top_secret", status: "blocked" },
        { src: "S3 Bucket", dst: "External API", type: "PHI", sens: "restricted", status: "blocked" },
        { src: "MCP Tool", dst: "External URL", type: "Internal", sens: "confidential", status: "monitored" },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{f.src}</td><td className="px-4 py-3 text-white/70">{f.dst}</td><td className="px-4 py-3 text-white/60">{f.type}</td><td className="px-4 py-3"><StatusBadge status={f.sens} /></td><td className="px-4 py-3"><StatusBadge status={f.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "detections" && (<div className="space-y-3">
      {[{ id: "DLP-012", channel: "AI Pipeline", detail: "PII detected in LLM prompt — customer SSNs", action: "Blocked + sanitized", severity: "critical" },
        { id: "DLP-011", channel: "MCP Tool", detail: "Agent tool call exfiltrating internal data to URL", action: "Blocked + alerted", severity: "critical" },
        { id: "DLP-010", channel: "Browser", detail: "Bulk download of classified documents", action: "Blocked + escalated", severity: "high" },
        { id: "DLP-009", channel: "Cloud Storage", detail: "S3 bucket ACL changed to public", action: "Reverted + alerted", severity: "high" },
      ].map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="text-xs text-white/40 ml-2">{d.channel}</span></div><StatusBadge status={d.severity} /></div>
        <p className="text-white/90 font-medium">{d.detail}</p><p className="text-xs text-white/50">Action: {d.action}</p></div>))}</div>)}
    {tab === "policies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active DLP Policies</h3>
      {[{ name: "Block PII in LLM Prompts", surfaces: "AI Pipeline", action: "Block + Sanitize", status: "active" },
        { name: "Prevent Secret Leakage", surfaces: "All", action: "Block + Alert", status: "active" },
        { name: "MCP Tool Data Guard", surfaces: "MCP Tools", action: "Block + Audit", status: "active" },
        { name: "Browser Upload Control", surfaces: "Browser", action: "Block > 10MB", status: "active" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.name}</p><p className="text-xs text-white/50">Surfaces: {p.surfaces} | Action: {p.action}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
