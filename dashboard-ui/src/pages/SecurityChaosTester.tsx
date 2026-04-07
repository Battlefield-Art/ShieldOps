import { useState } from "react";
import { Zap, TestTube2, Shield, AlertTriangle, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "experiments" | "resilience_scores" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "experiments", label: "Experiments" },
  { id: "resilience_scores", label: "Resilience Scores" },
  { id: "metrics", label: "Metrics" },
];

const EXPERIMENTS = [
  { id: "SCT-001", name: "Credential Revocation Storm", fault: "credential_revocation", target: "IAM Service", status: "completed", critical: 2 },
  { id: "SCT-002", name: "Firewall Rule Deletion", fault: "firewall_disruption", target: "Network Layer", status: "running", critical: 0 },
  { id: "SCT-003", name: "Certificate Expiry Cascade", fault: "certificate_expiry", target: "TLS Endpoints", status: "completed", critical: 1 },
  { id: "SCT-004", name: "IAM Policy Mutation", fault: "iam_policy_change", target: "AWS IAM", status: "scheduled", critical: 0 },
];

const SCORES = [
  { component: "Authentication Service", rating: "excellent", detection: "1.2s", recovery: "4.8s", score: 9.2 },
  { component: "Network Firewall", rating: "good", detection: "3.5s", recovery: "12.1s", score: 7.8 },
  { component: "Certificate Manager", rating: "poor", detection: "45.2s", recovery: "180s", score: 3.4 },
  { component: "IAM Policy Engine", rating: "fair", detection: "8.7s", recovery: "25.3s", score: 5.6 },
];

export default function SecurityChaosTester() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Chaos Tester" subtitle="Security-focused chaos engineering and resilience validation" icon={<Zap className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Experiments Run" value="47" icon={<TestTube2 className="h-5 w-5" />} />
        <MetricCard title="Avg Resilience" value="6.8" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Critical Failures" value="5" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Recovery Rate" value="92%" icon={<Activity className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Fault Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Credential", v: "12", c: "text-cyan-400" }, { l: "Firewall", v: "8", c: "text-emerald-400" }, { l: "Certificate", v: "15", c: "text-yellow-400" }, { l: "IAM Policy", v: "12", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "experiments" && (<div className="space-y-3">{EXPERIMENTS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.fault}</span></div><StatusBadge status={e.status} /></div><p className="text-white/90 text-sm font-medium">{e.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Target: {e.target}</span><span className={e.critical > 0 ? "text-red-400" : "text-white/40"}>{e.critical} critical failures</span></div></div>))}</div>)}
      {tab === "resilience_scores" && (<div className="space-y-3">{SCORES.map((s, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{s.component}</p><StatusBadge status={s.rating} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Detection: {s.detection}</span><span>Recovery: {s.recovery}</span><span className="text-cyan-400 font-mono">Score: {s.score}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Chaos Performance</h3>{[{ m: "Mean Detection Time", v: "14.6s", t: "-8.2s" }, { m: "Mean Recovery Time", v: "55.5s", t: "-22.1s" }, { m: "Alert Accuracy", v: "87%", t: "+11%" }, { m: "Failover Success Rate", v: "92%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
