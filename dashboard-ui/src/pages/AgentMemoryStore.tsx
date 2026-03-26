import { useState } from "react";
import { Brain, Database, Search, TrendingUp, Clock, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "memories" | "recall" | "learning";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "memories", label: "Memories" }, { id: "recall", label: "Recall" }, { id: "learning", label: "Learning" }];
export default function AgentMemoryStore() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Agent Memory Store" subtitle="Persistent episodic memory — agents learn from past investigations" icon={<Brain className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Memories Stored" value="12.4K" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Recall Accuracy" value="94.2%" icon={<Search className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="FP Patterns Learned" value="234" icon={<TrendingUp className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Cross-Agent Learnings" value="89" icon={<Zap className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Memory by Type</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "Investigation Outcomes", count: "5.2K", color: "text-cyan-400" }, { type: "FP Patterns", count: "3.1K", color: "text-emerald-400" }, { type: "Attack Signatures", count: "4.1K", color: "text-yellow-400" }].map((m) => (
        <div key={m.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{m.type}</p><p className={clsx("text-3xl font-bold mt-1", m.color)}>{m.count}</p></div>))}</div></div>)}
    {tab === "memories" && (<div className="space-y-3">
      {[{ id: "MEM-12400", agent: "agentic_mdr", type: "investigation_outcome", summary: "Credential theft via phishing — contained in 2.1 min", entities: ["admin@corp.com", "185.220.101.34"], age: "2h ago" },
        { id: "MEM-12399", agent: "breakout_defender", type: "attack_signature", summary: "LockBit 3.0 lateral movement pattern — SMB + WMI chain", entities: ["T1021.002", "T1047"], age: "4h ago" },
        { id: "MEM-12398", agent: "ai_triage_accelerator", type: "false_positive_pattern", summary: "Scheduled backup job triggers anomaly — suppress after 3 occurrences", entities: ["backup-svc", "cron-job-42"], age: "6h ago" },
      ].map((m) => (<div key={m.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{m.id}</span><span className="text-xs text-white/40 ml-2">{m.agent}</span></div><StatusBadge status={m.type} /></div>
        <p className="text-white/90 font-medium">{m.summary}</p><p className="text-xs text-white/50">Entities: {m.entities.join(", ")} | {m.age}</p></div>))}</div>)}
    {tab === "recall" && (<div className="card-surface p-6"><h3 className="section-heading">Recent Recalls</h3><div className="space-y-3">
      {[{ query: "Similar incidents to credential theft from 185.220.x.x", results: 7, strategy: "entity_match", accuracy: "96%", used_by: "agentic_mdr" },
        { query: "Past FP patterns for backup-related anomalies", results: 12, strategy: "pattern_match", accuracy: "92%", used_by: "ai_triage_accelerator" },
        { query: "LockBit containment playbooks that worked", results: 4, strategy: "semantic_search", accuracy: "94%", used_by: "ransomware_forensics" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{r.query}</p><p className="text-xs text-white/50">{r.results} results | Strategy: {r.strategy} | Accuracy: {r.accuracy} | Agent: {r.used_by}</p></div>))}</div></div>)}
    {tab === "learning" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Cross-Agent Learning Impact</h3>
      {[{ metric: "FP Rate Reduction", before: "8.2%", after: "2.1%", improvement: "-74%", source: "234 FP memories" },
        { metric: "Investigation Speed", before: "8.5 min", after: "2.3 min", improvement: "-73%", source: "5.2K outcome memories" },
        { metric: "Detection Accuracy", before: "89%", after: "97.8%", improvement: "+10%", source: "4.1K signature memories" },
      ].map((l, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{l.metric}</p><p className="text-xs text-white/50">{l.before} → {l.after} | Source: {l.source}</p></div><span className="text-emerald-400 font-mono text-sm">{l.improvement}</span></div>))}</div>)}
  </div>);
}
