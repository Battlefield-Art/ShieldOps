import { useState } from "react";
import { Cloud, AlertTriangle, Target, Shield, Crosshair } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "risks" | "attack_paths" | "remediation";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "risks", label: "Risk Rankings" }, { id: "attack_paths", label: "Attack Paths" }, { id: "remediation", label: "Remediation" }];
export default function CloudRiskRanker() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Cloud Risk Ranker" subtitle="Multi-cloud risk ranking linked to active attacker tactics" icon={<Cloud className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Critical Risks" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Attack Paths" value="23" icon={<Crosshair className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Actively Exploited" value="3" icon={<Target className="h-5 w-5 text-red-400" />} />
      <MetricCard title="MTTR (Critical)" value="4.2h" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk by Cloud (Ranked)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ cloud: "AWS", critical: 3, high: 8, exploited: 1 }, { cloud: "GCP", critical: 2, high: 5, exploited: 1 }, { cloud: "Azure", critical: 2, high: 4, exploited: 1 }].map((c) => (
        <div key={c.cloud} className="card-interactive p-4"><p className="text-white/90 font-medium mb-2">{c.cloud}</p><div className="space-y-1 text-sm"><p className="text-red-400">{c.critical} critical</p><p className="text-yellow-400">{c.high} high</p><p className="text-red-300">{c.exploited} actively exploited</p></div></div>))}</div></div>)}
    {tab === "risks" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Rank</th><th className="px-4 py-3">Finding</th><th className="px-4 py-3">Cloud</th><th className="px-4 py-3">Exploitability</th><th className="px-4 py-3">Severity</th></tr></thead>
      <tbody>{[
        { rank: 1, finding: "Public S3 with PII data", cloud: "AWS", exploit: "actively_exploited", sev: "critical" },
        { rank: 2, finding: "Over-privileged service account", cloud: "GCP", exploit: "exploit_available", sev: "critical" },
        { rank: 3, finding: "Unpatched Log4j in EKS pods", cloud: "AWS", exploit: "actively_exploited", sev: "critical" },
        { rank: 4, finding: "Network exposure via NSG", cloud: "Azure", exploit: "proof_of_concept", sev: "high" },
      ].map((r) => (<tr key={r.rank} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-cyan-400 font-mono">#{r.rank}</td><td className="px-4 py-3 text-white/90">{r.finding}</td><td className="px-4 py-3 text-white/60">{r.cloud}</td><td className="px-4 py-3"><StatusBadge status={r.exploit} /></td><td className="px-4 py-3"><StatusBadge status={r.sev} /></td></tr>))}</tbody></table></div>)}
    {tab === "attack_paths" && (<div className="space-y-3">
      {[{ id: "AP-001", path: "Public S3 → IAM Role → RDS Access", hops: 3, risk: "critical", exploited: true },
        { id: "AP-002", path: "NSG Exposure → VM → Lateral to K8s", hops: 4, risk: "high", exploited: false },
        { id: "AP-003", path: "OAuth Grant → API Access → Data Exfil", hops: 2, risk: "critical", exploited: true },
      ].map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="text-xs text-white/40 ml-2">{p.hops} hops</span></div><StatusBadge status={p.risk} /></div>
        <p className="text-white/90 font-medium font-mono text-sm">{p.path}</p>{p.exploited && <p className="text-xs text-red-400 mt-1">Actively exploited in the wild</p>}</div>))}</div>)}
    {tab === "remediation" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Prioritized Remediation</h3>
      {[{ action: "Restrict S3 bucket policy", target: "data-lake-prod", impact: "Blocks 2 attack paths", priority: "P0", status: "pending" },
        { action: "Rotate GCP service account key", target: "sa-admin@proj", impact: "Blocks 1 attack path", priority: "P0", status: "in_progress" },
        { action: "Patch Log4j in EKS", target: "prod-cluster", impact: "Removes critical CVE", priority: "P1", status: "pending" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.target} | {r.impact} | {r.priority}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
