import { useState } from "react";
import { Dna, Activity, Brain, Zap, GitBranch, ArrowUpRight, ArrowDownRight, Minus } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "fitness" | "prompts" | "learnings";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "fitness", label: "Fitness Leaderboard" }, { id: "prompts", label: "Prompt Evolution" }, { id: "learnings", label: "Learning Bus" }];

const TREND_ICON: Record<string, JSX.Element> = {
  improving: <ArrowUpRight className="h-4 w-4 text-green-400" />,
  declining: <ArrowDownRight className="h-4 w-4 text-red-400" />,
  stable: <Minus className="h-4 w-4 text-white/40" />,
};

export default function AgentEvolution() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Agent Evolution" subtitle="Self-evolving agent fleet — fitness tracking, prompt mutation, cross-agent learning propagation" icon={<Dna className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Fleet Fitness" value="0.847" icon={<Activity className="h-5 w-5 text-green-400" />} />
      <MetricCard title="Agents Evolving" value="23" icon={<Dna className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Prompt Mutations" value="67" icon={<GitBranch className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Learnings Shared" value="142" icon={<Brain className="h-5 w-5 text-purple-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>

    {tab === "overview" && (<div className="space-y-6">
      <div className="card-surface p-6"><h3 className="section-heading">Evolution Cycle Status</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { cycle: "EVO-2024-089", agents: 12, mutations: 8, improvement: "+3.2%", status: "completed" },
            { cycle: "EVO-2024-088", agents: 15, mutations: 11, improvement: "+1.8%", status: "completed" },
            { cycle: "EVO-2024-087", agents: 9, mutations: 5, improvement: "-0.4%", status: "rolled_back" },
          ].map((c) => (
            <div key={c.cycle} className="card-interactive p-4">
              <div className="flex items-center justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{c.cycle}</span><StatusBadge status={c.status === "rolled_back" ? "warning" : "healthy"} /></div>
              <p className="text-white/70 text-sm">{c.agents} agents · {c.mutations} mutations</p>
              <p className={clsx("text-sm font-medium mt-1", c.improvement.startsWith("+") ? "text-green-400" : "text-red-400")}>{c.improvement} fitness</p>
            </div>))}
        </div>
      </div>
      <div className="card-surface p-6"><h3 className="section-heading">Self-Evolution Pipeline</h3>
        <div className="flex items-center gap-2 text-sm overflow-x-auto pb-2">
          {["Measure Fitness", "Analyze Patterns", "Evolve Prompts", "Propagate Learnings", "Deploy Changes", "Validate"].map((step, i) => (
            <div key={step} className="flex items-center gap-2 whitespace-nowrap">
              {i > 0 && <span className="text-white/20">→</span>}
              <span className={clsx("px-3 py-1.5 rounded-md text-xs font-medium", i < 4 ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30" : "bg-white/5 text-white/50 border border-white/10")}>{step}</span>
            </div>))}
        </div>
      </div>
    </div>)}

    {tab === "fitness" && (<div className="card-surface overflow-hidden">
      <table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50">
        <th className="px-4 py-3">Rank</th><th className="px-4 py-3">Agent</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Fitness</th>
        <th className="px-4 py-3">Strongest</th><th className="px-4 py-3">Weakest</th><th className="px-4 py-3">Trend</th><th className="px-4 py-3">Gen</th>
      </tr></thead>
      <tbody>{[
        { rank: 1, id: "soc_analyst_01", type: "soc_analyst", fitness: 0.92, strongest: "accuracy", weakest: "cost", trend: "improving", gen: 7 },
        { rank: 2, id: "threat_hunter_01", type: "threat_hunter", fitness: 0.89, strongest: "safety", weakest: "speed", trend: "stable", gen: 5 },
        { rank: 3, id: "investigation_01", type: "investigation", fitness: 0.87, strongest: "accuracy", weakest: "learning_rate", trend: "improving", gen: 12 },
        { rank: 4, id: "remediation_01", type: "remediation", fitness: 0.85, strongest: "safety", weakest: "cost", trend: "stable", gen: 4 },
        { rank: 5, id: "xdr_01", type: "autonomous_xdr", fitness: 0.83, strongest: "speed", weakest: "accuracy", trend: "declining", gen: 3 },
        { rank: 6, id: "detection_01", type: "detection_engineering", fitness: 0.81, strongest: "accuracy", weakest: "speed", trend: "improving", gen: 8 },
        { rank: 7, id: "compliance_01", type: "compliance_auditor", fitness: 0.79, strongest: "safety", weakest: "learning_rate", trend: "stable", gen: 2 },
        { rank: 8, id: "incident_01", type: "incident_response", fitness: 0.76, strongest: "speed", weakest: "cost", trend: "declining", gen: 6 },
      ].map((a) => (<tr key={a.id} className="border-b border-white/5 hover:bg-white/5">
        <td className="px-4 py-3 text-white/50">#{a.rank}</td>
        <td className="px-4 py-3 font-mono text-xs text-cyan-400">{a.id}</td>
        <td className="px-4 py-3 text-white/70">{a.type}</td>
        <td className="px-4 py-3"><span className={clsx("font-medium", a.fitness >= 0.85 ? "text-green-400" : a.fitness >= 0.75 ? "text-yellow-400" : "text-red-400")}>{a.fitness.toFixed(3)}</span></td>
        <td className="px-4 py-3 text-green-400/70 text-xs">{a.strongest}</td>
        <td className="px-4 py-3 text-red-400/70 text-xs">{a.weakest}</td>
        <td className="px-4 py-3">{TREND_ICON[a.trend] || TREND_ICON.stable}</td>
        <td className="px-4 py-3 text-white/50">G{a.gen}</td>
      </tr>))}</tbody></table>
    </div>)}

    {tab === "prompts" && (<div className="space-y-4">
      <div className="card-surface p-6"><h3 className="section-heading">Active A/B Tests</h3>
        <div className="space-y-3">
          {[
            { agent: "investigation_01", node: "analyze_logs", champion: "v12 (0.84)", challenger: "v13 (0.87)", obs: "18/20", status: "testing" },
            { agent: "soc_analyst_01", node: "classify_event", champion: "v7 (0.91)", challenger: "v8 (0.89)", obs: "12/20", status: "testing" },
            { agent: "threat_hunter_01", node: "generate_hypotheses", champion: "v5 (0.78)", challenger: "v6 (0.82)", obs: "20/20", status: "challenger_wins" },
          ].map((t, i) => (
            <div key={i} className="card-interactive p-4">
              <div className="flex items-center justify-between mb-2">
                <div><span className="font-mono text-xs text-cyan-400">{t.agent}</span><span className="text-white/30 mx-2">→</span><span className="text-white/60 text-sm">{t.node}</span></div>
                <StatusBadge status={t.status === "challenger_wins" ? "healthy" : "info"} />
              </div>
              <div className="flex items-center gap-6 text-xs">
                <span className="text-white/50">Champion: <span className="text-white/80">{t.champion}</span></span>
                <span className="text-white/50">Challenger: <span className="text-cyan-400">{t.challenger}</span></span>
                <span className="text-white/40">Observations: {t.obs}</span>
              </div>
            </div>))}
        </div>
      </div>
      <div className="card-surface p-6"><h3 className="section-heading">Prompt Lineage</h3>
        <div className="space-y-2">
          {[
            { version: "v13", mutation: "instruction_refine", reason: "Reduce false positives in log analysis", gen: 13, score: 0.87, status: "testing" },
            { version: "v12", mutation: "example_add", reason: "Added SSH brute force detection example", gen: 12, score: 0.84, status: "active" },
            { version: "v11", mutation: "constraint_add", reason: "Require minimum 3 indicators before alert", gen: 11, score: 0.81, status: "superseded" },
            { version: "v10", mutation: "llm_rewrite", reason: "Cross-pollinated from threat_hunter pattern", gen: 10, score: 0.79, status: "superseded" },
          ].map((v) => (
            <div key={v.version} className="flex items-center gap-4 px-4 py-2 rounded border border-white/5 hover:border-white/10">
              <span className={clsx("font-mono text-sm w-8", v.status === "active" ? "text-green-400" : v.status === "testing" ? "text-cyan-400" : "text-white/30")}>{v.version}</span>
              <span className="text-xs bg-white/5 px-2 py-0.5 rounded text-white/50">{v.mutation}</span>
              <span className="text-sm text-white/70 flex-1">{v.reason}</span>
              <span className="text-xs text-white/40">G{v.gen}</span>
              <span className={clsx("text-sm font-medium", v.score >= 0.85 ? "text-green-400" : "text-white/60")}>{v.score.toFixed(2)}</span>
            </div>))}
        </div>
      </div>
    </div>)}

    {tab === "learnings" && (<div className="space-y-4">
      <div className="card-surface p-6"><h3 className="section-heading">Cross-Agent Learning Events</h3>
        <div className="space-y-3">
          {[
            { type: "false_positive_discovered", source: "soc_analyst_01", title: "Benign Terraform state refresh triggers alert", applied: 8, confidence: 0.92, scope: "fleet_wide" },
            { type: "attack_signature_learned", source: "threat_hunter_01", title: "Novel C2 beaconing via DNS TXT records", applied: 5, confidence: 0.88, scope: "related_types" },
            { type: "threshold_optimized", source: "detection_01", title: "Reduced alert noise by raising severity threshold to 0.65", applied: 4, confidence: 0.85, scope: "same_type" },
            { type: "playbook_improved", source: "remediation_01", title: "Added rollback step for K8s pod isolation", applied: 3, confidence: 0.81, scope: "related_types" },
            { type: "prompt_evolved", source: "investigation_01", title: "Improved hypothesis generation with MITRE ATT&CK mapping", applied: 6, confidence: 0.90, scope: "fleet_wide" },
          ].map((e, i) => (
            <div key={i} className="card-interactive p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Zap className="h-4 w-4 text-yellow-400" />
                  <span className="text-white/90 text-sm font-medium">{e.title}</span>
                </div>
                <span className="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-0.5 rounded">{e.applied} applied</span>
              </div>
              <div className="flex items-center gap-4 text-xs text-white/50">
                <span>Source: <span className="text-cyan-400">{e.source}</span></span>
                <span className="bg-white/5 px-2 py-0.5 rounded">{e.type}</span>
                <span>Confidence: {(e.confidence * 100).toFixed(0)}%</span>
                <span className="text-white/30">{e.scope}</span>
              </div>
            </div>))}
        </div>
      </div>
      <div className="card-surface p-6"><h3 className="section-heading">Learning Bus Stats</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Total Events", value: "142" },
            { label: "Active Subscribers", value: "47" },
            { label: "Application Rate", value: "72%" },
            { label: "Shared Patterns", value: "31" },
          ].map((s) => (
            <div key={s.label} className="text-center p-3 bg-white/5 rounded-lg">
              <p className="text-lg font-bold text-white/90">{s.value}</p>
              <p className="text-xs text-white/50">{s.label}</p>
            </div>))}
        </div>
      </div>
    </div>)}
  </div>);
}
