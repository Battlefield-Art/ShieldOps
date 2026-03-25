import { useState } from "react";
import { Siren, ArrowRight, Clock, Users, Zap, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "queue" | "routing" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "queue", label: "Triage Queue" },
  { id: "routing", label: "Routing Decisions" }, { id: "metrics", label: "Triage Metrics" },
];

export default function IncidentTriage() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Incident Triage" subtitle="Automated severity classification, context enrichment, and intelligent routing" icon={<Siren className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Triaged (24h)" value="47" icon={<Zap className="h-5 w-5" />} />
        <MetricCard title="Auto-Resolved" value="28" icon={<BarChart3 className="h-5 w-5" />} />
        <MetricCard title="Avg Triage Time" value="18s" icon={<Clock className="h-5 w-5" />} />
        <MetricCard title="Classification Accuracy" value="94%" icon={<Users className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Triage Summary (24h)</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[{ sev: "SEV1", count: 2, color: "text-red-400" }, { sev: "SEV2", count: 8, color: "text-orange-400" }, { sev: "SEV3", count: 18, color: "text-yellow-400" }, { sev: "SEV4/5", count: 19, color: "text-emerald-400" }].map((s) => (
              <div key={s.sev} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.sev}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "queue" && (
        <div className="space-y-3">
          {[
            { id: "INC-4821", title: "Production DB connection pool exhausted", sev: "SEV1", category: "Availability", team: "platform-sre", ttm: "12 min", status: "investigating" },
            { id: "INC-4822", title: "Authentication service 5xx spike", sev: "SEV2", category: "Availability", team: "auth-team", ttm: "8 min", status: "routed" },
            { id: "INC-4823", title: "Suspicious API key usage from new geo", sev: "SEV2", category: "Security", team: "security-ops", ttm: "5 min", status: "enriching" },
            { id: "INC-4824", title: "Deployment canary health check failures", sev: "SEV3", category: "Configuration", team: "platform-sre", ttm: "—", status: "auto_resolved" },
          ].map((inc) => (
            <div key={inc.id} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div><div className="flex items-center gap-2 mb-1"><span className="font-mono text-xs text-cyan-400">{inc.id}</span><StatusBadge status={inc.sev === "SEV1" ? "critical" : inc.sev === "SEV2" ? "high" : "medium"} /><StatusBadge status={inc.status} /></div><p className="text-white/90 font-medium">{inc.title}</p></div>
                <span className="text-xs text-white/40">TTM: {inc.ttm}</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-white/50"><span>{inc.category}</span><ArrowRight className="h-3 w-3" /><span>{inc.team}</span></div>
            </div>
          ))}
        </div>
      )}
      {tab === "routing" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Team Routing Performance</h3>
          {[
            { team: "platform-sre", routed: 18, correct: 16, rerouted: 2, load: "optimal" },
            { team: "security-ops", routed: 12, correct: 11, rerouted: 1, load: "optimal" },
            { team: "auth-team", routed: 8, correct: 8, rerouted: 0, load: "under" },
            { team: "data-team", routed: 9, correct: 7, rerouted: 2, load: "heavy" },
          ].map((t) => (
            <div key={t.team} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{t.team}</p><p className="text-xs text-white/50">{t.routed} incidents | {t.correct} correct first-time | {t.rerouted} rerouted</p></div>
              <StatusBadge status={t.load === "heavy" ? "warning" : "active"} />
            </div>
          ))}
        </div>
      )}
      {tab === "metrics" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Triage Performance</h3>
          <div className="grid grid-cols-2 gap-4">
            {[{ metric: "Avg Triage Time", value: "18s", target: "<30s" }, { metric: "Classification Accuracy", value: "94%", target: ">90%" }, { metric: "Auto-Resolution Rate", value: "60%", target: ">50%" }, { metric: "Reroute Rate", value: "6%", target: "<10%" }].map((m) => (
              <div key={m.metric} className="card-interactive p-4"><p className="text-sm text-white/60">{m.metric}</p><p className="text-2xl font-bold text-white mt-1">{m.value}</p><p className="text-xs text-white/40">Target: {m.target}</p></div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
