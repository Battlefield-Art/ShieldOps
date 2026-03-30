import { useState } from "react";
import {
  TrendingUp,
  Activity,
  BarChart3,
  Cpu,
  Server,
  Clock,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "predictions" | "scaling" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "predictions", label: "Predictions" },
  { id: "scaling", label: "Scaling History" },
  { id: "metrics", label: "Metrics" },
];

const PREDICTIONS = [
  {
    id: "P-001",
    resource: "api-gateway-prod",
    type: "SCALE_OUT",
    confidence: 0.92,
    eta: "2h 15m",
    reason: "Traffic spike predicted from historical pattern",
  },
  {
    id: "P-002",
    resource: "worker-pool-batch",
    type: "SCALE_UP",
    confidence: 0.87,
    eta: "45m",
    reason: "Memory pressure approaching threshold",
  },
  {
    id: "P-003",
    resource: "cache-cluster-01",
    type: "SCALE_DOWN",
    confidence: 0.78,
    eta: "6h",
    reason: "Off-peak hours approaching, reduced load expected",
  },
  {
    id: "P-004",
    resource: "ml-inference-gpu",
    type: "SCALE_OUT",
    confidence: 0.95,
    eta: "30m",
    reason: "Batch job queue depth increasing rapidly",
  },
];

const SCALING_HISTORY = [
  {
    time: "14:32",
    resource: "api-gateway-prod",
    action: "Scale Out 3→5 pods",
    status: "success",
    savings: "$0 (demand-driven)",
  },
  {
    time: "12:15",
    resource: "worker-pool-batch",
    action: "Scale Down 8→4 pods",
    status: "success",
    savings: "$12.40/hr saved",
  },
  {
    time: "09:00",
    resource: "cache-cluster-01",
    action: "Scale Up r6g.large→r6g.xlarge",
    status: "success",
    savings: "Prevented OOM",
  },
  {
    time: "06:45",
    resource: "ml-inference-gpu",
    action: "Scale In 4→2 instances",
    status: "rolled_back",
    savings: "Rolled back — latency spike",
  },
];

export default function PredictiveScaler() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader
        title="Predictive Scaler"
        subtitle="Proactive infrastructure scaling with demand forecasting"
        icon={<TrendingUp className="h-6 w-6" />}
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Active Predictions"
          value="18"
          icon={<Activity className="h-5 w-5" />}
        />
        <MetricCard
          title="Scaling Events (24h)"
          value="47"
          icon={<Server className="h-5 w-5 text-cyan-400" />}
        />
        <MetricCard
          title="Accuracy"
          value="94.2%"
          icon={<BarChart3 className="h-5 w-5 text-emerald-400" />}
        />
        <MetricCard
          title="Cost Savings"
          value="$2,340"
          icon={<Cpu className="h-5 w-5 text-yellow-400" />}
        />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              "tab-item",
              tab === t.id && "tab-item-active"
            )}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6">
          <h3 className="section-heading">Scaling Intelligence</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              {
                l: "Pre-emptive Scales",
                v: "34",
                c: "text-emerald-400",
              },
              {
                l: "Reactive Scales",
                v: "13",
                c: "text-yellow-400",
              },
              { l: "Rollbacks", v: "2", c: "text-red-400" },
            ].map((s) => (
              <div
                key={s.l}
                className="card-interactive p-4 text-center"
              >
                <p className="text-sm text-white/60">{s.l}</p>
                <p
                  className={clsx(
                    "text-2xl font-bold mt-1",
                    s.c
                  )}
                >
                  {s.v}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "predictions" && (
        <div className="space-y-3">
          {PREDICTIONS.map((p) => (
            <div key={p.id} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className="font-mono text-xs text-cyan-400">
                    {p.id}
                  </span>
                  <span className="ml-2 text-white/90 font-medium">
                    {p.resource}
                  </span>
                </div>
                <StatusBadge
                  status={
                    p.confidence > 0.9
                      ? "critical"
                      : p.confidence > 0.8
                        ? "high"
                        : "medium"
                  }
                />
              </div>
              <p className="text-white/70 text-sm">{p.reason}</p>
              <div className="flex items-center gap-4 mt-2 text-xs text-white/50">
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" /> ETA: {p.eta}
                </span>
                <span>
                  Confidence: {(p.confidence * 100).toFixed(0)}%
                </span>
                <span className="text-cyan-400">{p.type}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "scaling" && (
        <div className="space-y-3">
          {SCALING_HISTORY.map((h, i) => (
            <div key={i} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className="font-mono text-xs text-white/50">
                    {h.time}
                  </span>
                  <span className="ml-2 text-white/90 font-medium">
                    {h.resource}
                  </span>
                </div>
                <StatusBadge status={h.status} />
              </div>
              <p className="text-white/70 text-sm">{h.action}</p>
              <p className="text-xs text-white/50 mt-1">
                {h.savings}
              </p>
            </div>
          ))}
        </div>
      )}
      {tab === "metrics" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Performance Trends</h3>
          {[
            {
              m: "Prediction Accuracy",
              v: "94.2%",
              t: "+2.1%",
            },
            {
              m: "Avg Lead Time",
              v: "47 min",
              t: "+5 min",
            },
            {
              m: "Cost Savings Rate",
              v: "23.4%",
              t: "+3.2%",
            },
            {
              m: "Rollback Rate",
              v: "4.3%",
              t: "-1.1%",
            },
          ].map((x, i) => (
            <div
              key={i}
              className="card-interactive p-4 flex items-center justify-between"
            >
              <div>
                <p className="text-white/90 font-medium">{x.m}</p>
                <p className="text-xs text-white/50">{x.t}</p>
              </div>
              <span className="text-cyan-400 font-mono">{x.v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
