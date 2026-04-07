import { useState } from "react";
import { MessageSquare, Bell, CheckCircle, Clock, Users } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "notifications" | "channels" | "ack";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "notifications", label: "Notifications" }, { id: "channels", label: "Channels" }, { id: "ack", label: "Acknowledgments" }];
export default function IncidentCommunicator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Incident Communicator" subtitle="Auto-notify stakeholders — Slack, PagerDuty, email, SMS" icon={<MessageSquare className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Notifications Sent" value="234" icon={<Bell className="h-5 w-5" />} />
      <MetricCard title="Acknowledged" value="98.3%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Avg Ack Time" value="2.1 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Stakeholders" value="47" icon={<Users className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Notification Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ ch: "Slack", sent: 89, acked: 87, color: "text-emerald-400" }, { ch: "PagerDuty", sent: 45, acked: 45, color: "text-emerald-400" }, { ch: "Email", sent: 67, acked: 64, color: "text-cyan-400" }, { ch: "SMS", sent: 33, acked: 34, color: "text-emerald-400" }].map((c) => (
        <div key={c.ch} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.ch}</p><p className={clsx("text-2xl font-bold mt-1", c.color)}>{c.sent}</p><p className="text-xs text-white/40">{c.acked} acknowledged</p></div>))}</div></div>)}
    {tab === "notifications" && (<div className="space-y-3">
      {[{ incident: "IR-089", msg: "CRITICAL: Admin credential compromise — war room open", channels: ["Slack", "PagerDuty", "SMS"], time: "2 min ago", status: "acknowledged" },
        { incident: "IR-088", msg: "HIGH: Phishing campaign detected — 3 users clicked", channels: ["Slack", "Email"], time: "1h ago", status: "acknowledged" },
      ].map((n, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{n.msg}</p><StatusBadge status={n.status} /></div>
        <p className="text-xs text-white/50">{n.incident} | {n.channels.join(", ")} | {n.time}</p></div>))}</div>)}
    {tab === "channels" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Channel</th><th className="px-4 py-3">Sent</th><th className="px-4 py-3">Delivered</th><th className="px-4 py-3">Ack Rate</th><th className="px-4 py-3">Avg Ack Time</th></tr></thead>
      <tbody>{[
        { ch: "Slack", sent: 89, delivered: 89, ack: "97.8%", time: "1.2 min" },
        { ch: "PagerDuty", sent: 45, delivered: 45, ack: "100%", time: "0.5 min" },
        { ch: "Email", sent: 67, delivered: 65, ack: "95.5%", time: "8.3 min" },
        { ch: "SMS", sent: 33, delivered: 33, ack: "97.0%", time: "1.8 min" },
      ].map((c, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{c.ch}</td><td className="px-4 py-3 text-white/80">{c.sent}</td><td className="px-4 py-3 text-white/70">{c.delivered}</td><td className="px-4 py-3 text-emerald-400">{c.ack}</td><td className="px-4 py-3 text-white/60">{c.time}</td></tr>))}</tbody></table></div>)}
    {tab === "ack" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Unacknowledged</h3>
      {[{ person: "exec-vp@corp.com", channel: "Email", incident: "IR-089", sent: "15 min ago", escalation: "SMS in 5 min" },
      ].map((u, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{u.person}</p><p className="text-xs text-white/50">{u.channel} | {u.incident} | Sent: {u.sent}</p></div><p className="text-xs text-yellow-400">Escalation: {u.escalation}</p></div>))}</div>)}
  </div>);
}
