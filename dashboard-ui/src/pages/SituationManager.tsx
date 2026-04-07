import { useState } from "react";
import { LayoutList, Zap, Clock, CheckCircle, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "queue" | "resolved" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "queue", label: "Situations Queue" }, { id: "resolved", label: "Resolved" }, { id: "metrics", label: "Metrics" }];
export default function SituationManager() {
  const [tab, setTab] = useState<TabId>("queue");
  return (<div className="space-y-6">
    <PageHeader title="Situation Manager" subtitle="Outcome-centric queue — 3 situations, not 847 alerts" icon={<LayoutList className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Situations" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Resolved Today" value="12" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Avg Resolution" value="4.2 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Analyst Actions Saved" value="89%" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "queue" && (<div className="space-y-4">
      {[{ id: "SIT-005", priority: "p0_active_attack", title: "Active Credential Compromise → Cloud Data Exfiltration", narrative: "An attacker compromised admin@corp.com credentials via phishing (Okta alert), escalated privileges in AWS (CloudTrail), and is actively downloading customer data from S3 (Wiz finding). 3 vendors corroborate. Blast radius: 2.3TB customer data.", alerts: 12, vendors: 3, actions: [{ action: "Revoke all sessions for admin@corp.com", confidence: 0.97 }, { action: "Block S3 download + rotate IAM keys", confidence: 0.94 }] },
        { id: "SIT-004", priority: "p1_high_risk", title: "Web Server Exploitation with Lateral Movement", narrative: "web-server-prod was exploited via CVE-2026-XXXX (Wiz), Cobalt Strike beacon installed (Falcon), attempting lateral movement via SMB (Splunk NDR). Currently contained to DMZ.", alerts: 8, vendors: 3, actions: [{ action: "Isolate web-server-prod from network", confidence: 0.92 }] },
        { id: "SIT-003", priority: "p2_investigation", title: "Insider Data Hoarding — Flight Risk Employee", narrative: "john.d@corp.com (flagged as flight risk by HR) has downloaded 4.7GB from shared drives in 48 hours (Defender DLP), accessed customer DB at 2am (Splunk). Pattern matches data theft preparation.", alerts: 5, vendors: 2, actions: [{ action: "Enable enhanced monitoring for john.d", confidence: 0.85 }] },
      ].map((s) => (<div key={s.id} className="card-surface p-6"><div className="flex items-start justify-between mb-3"><div><div className="flex items-center gap-2"><span className="font-mono text-sm text-cyan-400">{s.id}</span><StatusBadge status={s.priority} /></div><h3 className="text-white font-semibold mt-1">{s.title}</h3></div><span className="text-xs text-white/40">{s.alerts} alerts | {s.vendors} vendors</span></div>
        <p className="text-sm text-white/70 mb-4">{s.narrative}</p>
        <div className="space-y-2">{s.actions.map((a, i) => (<div key={i} className="flex items-center justify-between p-2 rounded bg-cyan-900/20 border border-cyan-500/20"><span className="text-sm text-white/90">{a.action}</span><button className="btn-primary px-3 py-1 text-xs">Execute ({(a.confidence * 100).toFixed(0)}%)</button></div>))}</div></div>))}</div>)}
    {tab === "resolved" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Resolved Today</h3>
      {[{ id: "SIT-002", title: "Brute Force → Account Takeover Attempt", resolution: "resolved_auto", time: "1.8 min", method: "Auto-blocked IP + forced MFA reset" },
        { id: "SIT-001", title: "Ransomware Pre-staging Detected", resolution: "resolved_analyst", time: "8.2 min", method: "Analyst confirmed + full containment" },
      ].map((r) => (<div key={r.id} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.title}</p><p className="text-xs text-white/50">{r.method} | {r.time}</p></div><StatusBadge status={r.resolution} /></div>))}</div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Situation vs Alert Dashboard</h3>
      {[{ metric: "Items to Review", situations: "3 situations", alerts: "847 alerts", improvement: "282x reduction" },
        { metric: "Time to Understand", situations: "30 seconds (narrative)", alerts: "15 min (alert triage)", improvement: "30x faster" },
        { metric: "Actions per Item", situations: "1-2 recommended", alerts: "Manual investigation", improvement: "Pre-computed" },
        { metric: "False Positive Rate", situations: "0% (pre-correlated)", alerts: "67% individual FPs", improvement: "Eliminated" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4"><div className="flex justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">Situations: {m.situations} | Alerts: {m.alerts}</p></div><span className="text-emerald-400 text-sm">{m.improvement}</span></div></div>))}</div>)}
  </div>);
}
