import { useState } from "react";
import { GitPullRequest, AlertTriangle, Shield, CheckCircle, Clock, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "changes" | "blast_radius" | "history";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "changes", label: "Pending Changes" },
  { id: "blast_radius", label: "Blast Radius" }, { id: "history", label: "History" },
];

export default function ChangeRiskAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Change Risk Analyzer" subtitle="Pre-deployment risk assessment, blast radius prediction, and approval routing" icon={<GitPullRequest className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Pending Changes" value="4" icon={<GitPullRequest className="h-5 w-5" />} />
        <MetricCard title="High Risk" value="1" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Auto-Approved" value="67%" icon={<CheckCircle className="h-5 w-5" />} />
        <MetricCard title="Avg Assessment Time" value="4.2s" icon={<Clock className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Risk Distribution (30d)</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[{ level: "Minimal", count: 42, color: "text-emerald-400" }, { level: "Low", count: 28, color: "text-cyan-400" }, { level: "Medium", count: 14, color: "text-yellow-400" }, { level: "High/Critical", count: 4, color: "text-red-400" }].map((r) => (
              <div key={r.level} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{r.level}</p><p className={clsx("text-3xl font-bold mt-1", r.color)}>{r.count}</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "changes" && (
        <div className="space-y-3">
          {[
            { id: "CR-892", title: "DB migration v42 — add index on users.email", type: "Database Migration", risk: 82, decision: "Require Senior Review", services: 3, env: "production" },
            { id: "CR-893", title: "Feature flag: enable new auth flow", type: "Feature Flag", risk: 25, decision: "Auto-Approve", services: 1, env: "production" },
            { id: "CR-894", title: "K8s HPA config update", type: "Infrastructure", risk: 45, decision: "Require Review", services: 2, env: "staging" },
            { id: "CR-895", title: "API v2 deprecation rollout", type: "Deployment", risk: 68, decision: "Require Review", services: 4, env: "production" },
          ].map((c) => (
            <div key={c.id} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div><div className="flex items-center gap-2 mb-1"><span className="font-mono text-xs text-cyan-400">{c.id}</span><StatusBadge status={c.risk > 70 ? "critical" : c.risk > 40 ? "medium" : "low"} /></div><p className="text-white/90 font-medium">{c.title}</p></div>
                <span className={clsx("text-lg font-bold", c.risk > 70 ? "text-red-400" : c.risk > 40 ? "text-yellow-400" : "text-emerald-400")}>{c.risk}%</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-white/50"><span>{c.type}</span><span>|</span><span>{c.services} services</span><span>|</span><span>{c.env}</span><span>|</span><span className="text-cyan-400">{c.decision}</span></div>
            </div>
          ))}
        </div>
      )}
      {tab === "blast_radius" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Blast Radius Predictions</h3>
          {[
            { change: "CR-892 (DB Migration)", services: ["api-gateway", "user-service", "billing"], users: "50K", recovery: "45 min", cascading: ["payment processing"] },
            { change: "CR-895 (API v2 Deprecation)", services: ["api-gateway", "sdk", "docs", "partner-portal"], users: "120K", recovery: "30 min", cascading: ["partner integrations"] },
          ].map((b, i) => (
            <div key={i} className="card-interactive p-4">
              <p className="text-white/90 font-medium mb-2">{b.change}</p>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div><p className="text-white/40">Affected Services</p><p className="text-white/80">{b.services.join(", ")}</p></div>
                <div><p className="text-white/40">Users at Risk</p><p className="text-white font-bold">{b.users}</p></div>
                <div><p className="text-white/40">Est. Recovery</p><p className="text-white/80">{b.recovery}</p></div>
              </div>
              {b.cascading.length > 0 && <p className="text-xs text-red-400 mt-2">Cascading: {b.cascading.join(", ")}</p>}
            </div>
          ))}
        </div>
      )}
      {tab === "history" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Prediction Accuracy (30d)</h3>
          <div className="grid grid-cols-2 gap-4">
            {[{ metric: "Risk Prediction Accuracy", value: "91%" }, { metric: "Blast Radius Accuracy", value: "84%" }, { metric: "Changes Analyzed", value: "88" }, { metric: "Rollbacks Prevented", value: "6" }].map((m) => (
              <div key={m.metric} className="card-interactive p-4"><p className="text-sm text-white/60">{m.metric}</p><p className="text-2xl font-bold text-white mt-1">{m.value}</p></div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
