import { useState } from "react";
import { MessageSquare, Brain, Zap, Clock, Search, Send } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "chat" | "history" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "chat", label: "Assistant" }, { id: "history", label: "History" }, { id: "metrics", label: "Metrics" }];
export default function AISOCAssistant() {
  const [tab, setTab] = useState<TabId>("chat");
  return (<div className="space-y-6">
    <PageHeader title="AI SOC Assistant" subtitle="Natural language investigation across any vendor — powered by Claude" icon={<MessageSquare className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Queries Handled (24h)" value="89" icon={<Search className="h-5 w-5" />} />
      <MetricCard title="Avg Response" value="3.2s" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Actions Suggested" value="134" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Analyst Satisfaction" value="4.8/5" icon={<Brain className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "chat" && (<div className="card-surface p-6 space-y-4"><div className="space-y-3">
      {[{ role: "analyst", msg: "What happened to user admin@corp.com in the last 24 hours?" },
        { role: "assistant", msg: "I found 3 significant events for admin@corp.com across Okta and AWS:\n\n1. **Impossible travel** — Login from New York (09:14 UTC) then Mumbai (09:19 UTC). Flagged by Okta.\n2. **IAM role assumption** — AssumeRole to AdministratorAccess in AWS us-east-1 at 09:22 UTC.\n3. **S3 bulk download** — 2.3GB downloaded from customer-data-prod bucket at 09:25 UTC.\n\n**Assessment:** This looks like a credential compromise → privilege escalation → data exfiltration chain. Confidence: 0.94.\n\n**Suggested actions:**\n- Revoke all active sessions for admin@corp.com\n- Rotate AWS credentials\n- Block the Mumbai IP (203.0.113.42)" },
        { role: "analyst", msg: "Execute the session revocation and credential rotation" },
        { role: "assistant", msg: "Executing 2 actions:\n\n1. ✅ Okta: All sessions revoked for admin@corp.com (0.3s)\n2. ✅ AWS: Access keys rotated, old keys deactivated (0.8s)\n\nThe Mumbai IP has been added to the blocklist. I recommend opening an incident for full investigation." },
      ].map((m, i) => (<div key={i} className={clsx("p-3 rounded-lg max-w-[85%]", m.role === "analyst" ? "ml-auto bg-cyan-900/30 border border-cyan-500/20" : "bg-white/5")}><p className="text-xs text-white/40 mb-1">{m.role === "analyst" ? "You" : "ShieldOps AI"}</p><p className="text-sm text-white/90 whitespace-pre-line">{m.msg}</p></div>))}
    </div><div className="flex gap-2"><input className="flex-1 bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-sm text-white/90 placeholder-white/30" placeholder="Ask about any security event..." /><button className="btn-primary px-4 py-2 flex items-center gap-1"><Send className="h-4 w-4" /> Ask</button></div></div>)}
    {tab === "history" && (<div className="space-y-3">
      {[{ query: "Show me all failed logins in the last hour", type: "investigation", sources: "Splunk, Okta", time: "2.1s", actions: 0 },
        { query: "Is the CVE-2024-1234 patched on prod servers?", type: "compliance_check", sources: "Elastic, Asset DB", time: "4.3s", actions: 2 },
        { query: "What's the current threat level for our AWS accounts?", type: "system_status", sources: "CloudTrail, GuardDuty", time: "3.8s", actions: 1 },
        { query: "Explain the T1078 technique in our context", type: "explainer", sources: "MITRE ATT&CK, Incidents", time: "1.9s", actions: 0 },
      ].map((q, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{q.query}</p><StatusBadge status={q.type} /></div>
        <p className="text-xs text-white/50">Sources: {q.sources} | Response: {q.time} | {q.actions} actions</p></div>))}</div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">AI Assistant vs Charlotte AI</h3>
      {[{ metric: "Vendor Coverage", ours: "17 vendors", competitor: "Falcon only", advantage: "17x broader" },
        { metric: "Response Time", ours: "3.2 sec", competitor: "~5 sec", advantage: "36% faster" },
        { metric: "Action Execution", ours: "Cross-vendor", competitor: "Falcon actions only", advantage: "Open" },
        { metric: "Reasoning Model", ours: "Claude (latest)", competitor: "Proprietary", advantage: "Transparent" },
        { metric: "Investigation Depth", ours: "Multi-source correlation", competitor: "Single data lake", advantage: "Richer context" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">ShieldOps: {m.ours} | Competitor: {m.competitor}</p></div><span className="text-emerald-400 text-sm">{m.advantage}</span></div>))}</div>)}
  </div>);
}
