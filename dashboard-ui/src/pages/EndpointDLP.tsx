import { useState } from "react";
import { Monitor, Shield, Ban, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "movements" | "violations" | "policies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "movements", label: "Data Movements" }, { id: "violations", label: "Violations" }, { id: "policies", label: "Policies" }];
export default function EndpointDLP() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Endpoint DLP" subtitle="Endpoint data loss prevention with AI pipeline awareness" icon={<Monitor className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Endpoints Monitored" value="2.4K" icon={<Monitor className="h-5 w-5" />} />
      <MetricCard title="Blocked (24h)" value="23" icon={<Ban className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Data Movements" value="12.4K" icon={<Eye className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Policy Compliance" value="97%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Data Channels (24h)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ ch: "Clipboard/Paste", movements: 4200, blocked: 8, color: "text-yellow-400" }, { ch: "USB/Removable", movements: 89, blocked: 5, color: "text-red-400" }, { ch: "AI Prompt Paste", movements: 1200, blocked: 7, color: "text-red-400" }, { ch: "Upload/Email", movements: 6911, blocked: 3, color: "text-white/70" }].map((c) => (
        <div key={c.ch} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.ch}</p><p className="text-xl font-bold text-white/80 mt-1">{c.movements.toLocaleString()}</p><p className="text-xs text-red-400">{c.blocked} blocked</p></div>))}</div></div>)}
    {tab === "movements" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">User</th><th className="px-4 py-3">Channel</th><th className="px-4 py-3">Data</th><th className="px-4 py-3">Action</th></tr></thead>
      <tbody>{[
        { user: "dev@corp.com", ch: "ai_prompt_paste", data: "API keys pasted into ChatGPT", action: "blocked" },
        { user: "analyst@corp.com", ch: "usb", data: "Customer CSV to USB drive", action: "blocked" },
        { user: "admin@corp.com", ch: "clipboard", data: "DB credentials to Slack", action: "warned" },
        { user: "intern@corp.com", ch: "screen_capture", data: "Screenshot of PII dashboard", action: "logged" },
      ].map((m, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{m.user}</td><td className="px-4 py-3"><StatusBadge status={m.ch} /></td><td className="px-4 py-3 text-white/70">{m.data}</td><td className="px-4 py-3"><StatusBadge status={m.action} /></td></tr>))}</tbody></table></div>)}
    {tab === "violations" && (<div className="space-y-3">
      {[{ id: "EDLP-023", user: "dev@corp.com", violation: "Pasted AWS credentials into LLM prompt", channel: "ai_prompt_paste", severity: "critical" },
        { id: "EDLP-022", user: "analyst@corp.com", violation: "Exported 2.3GB customer data to USB", channel: "usb", severity: "critical" },
        { id: "EDLP-021", user: "admin@corp.com", violation: "Shared DB connection string via clipboard to Slack", channel: "clipboard", severity: "high" },
      ].map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="text-xs text-white/40 ml-2">{v.user}</span></div><StatusBadge status={v.severity} /></div>
        <p className="text-white/90 font-medium">{v.violation}</p><p className="text-xs text-white/50">Channel: {v.channel}</p></div>))}</div>)}
    {tab === "policies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Endpoint DLP Policies</h3>
      {[{ name: "Block AI Prompt Secrets", ch: "AI Prompt Paste", action: "Block + Strip", status: "active" },
        { name: "USB Data Control", ch: "USB/Removable", action: "Block PII/PCI", status: "active" },
        { name: "Clipboard Monitor", ch: "Clipboard", action: "Warn on secrets", status: "active" },
        { name: "Screenshot Control", ch: "Screen Capture", action: "Log + watermark", status: "active" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.name}</p><p className="text-xs text-white/50">{p.ch} | Action: {p.action}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
