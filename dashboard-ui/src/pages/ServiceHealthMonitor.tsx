import { useState } from "react";
import {
  Activity,
  Heart,
  AlertTriangle,
  Server,
  Clock,
  Zap,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "services" | "degradation" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "services", label: "Services" },
  { id: "degradation", label: "Degradation" },
  { id: "metrics", label: "Metrics" },
];

const SERVICES = [
  {
    name: "api-gateway",
    tier: "Tier 1",
    status: "healthy",
    latency: "12ms",
    uptime: "99.99%",
    errors: 0,
  },
  {
    name: "auth-service",
    tier: "Tier 1",
    status: "healthy",
    latency: "8ms",
    uptime: "99.98%",
    errors: 2,
  },
  {
    name: "payment-processor",
    tier: "Tier 1",
    status: "degraded",
    latency: "245ms",
    uptime: "99.85%",
    errors: 47,
  },
  {
    name: "notification-svc",
    tier: "Tier 2",
    status: "healthy",
    latency: "15ms",
    uptime: "99.95%",
    errors: 0,
  },
  {
    name: "analytics-pipeline",
    tier: "Tier 3",
    status: "healthy",
    latency: "340ms",
    uptime: "99.90%",
    errors: 5,
  },
  {
    name: "search-indexer",
    tier: "Tier 2",
    status: "unhealthy",
    latency: "timeout",
    uptime: "97.20%",
    errors: 1243,
  },
];

const DEGRADATION_EVENTS = [
  {
    id: "D-001",
    service: "payment-processor",
    type: "Latency spike",
    started: "14:22",
    duration: "38 min",
    impact: "high",
    action: "Auto-scaled to 5 replicas",
  },
  {
    id: "D-002",
    service: "search-indexer",
    type: "Connection pool exhaustion",
    started: "13:45",
    duration: "1h 15m",
    impact: "critical",
    action: "Restarted pods, investigating root cause",
  },
  {
    id: "D-003",
    service: "auth-service",
    type: "Elevated error rate",
    started: "11:30",
    duration: "12 min",
    impact: "medium",
    action: "Resolved — upstream DNS issue",
  },
];

export default function ServiceHealthMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader
        title="Service Health Monitor"
        subtitle="Real-time microservice health and dependency tracking"
        icon={<Activity className="h-6 w-6" />}
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Services Monitored"
          value="42"
          icon={<Server className="h-5 w-5" />}
        />
        <MetricCard
          title="Healthy"
          value="38"
          icon={<Heart className="h-5 w-5 text-emerald-400" />}
        />
        <MetricCard
          title="Degraded"
          value="3"
          icon={
            <AlertTriangle className="h-5 w-5 text-yellow-400" />
          }
        />
        <MetricCard
          title="Avg Latency"
          value="23ms"
          icon={<Zap className="h-5 w-5 text-cyan-400" />}
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
          <h3 className="section-heading">Fleet Health</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              {
                l: "Tier 1",
                v: "2/3 Healthy",
                c: "text-yellow-400",
              },
              {
                l: "Tier 2",
                v: "1/2 Healthy",
                c: "text-red-400",
              },
              {
                l: "Tier 3",
                v: "1/1 Healthy",
                c: "text-emerald-400",
              },
              {
                l: "Overall",
                v: "90.5%",
                c: "text-cyan-400",
              },
            ].map((s) => (
              <div
                key={s.l}
                className="card-interactive p-4 text-center"
              >
                <p className="text-sm text-white/60">{s.l}</p>
                <p
                  className={clsx(
                    "text-xl font-bold mt-1",
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
      {tab === "services" && (
        <div className="space-y-3">
          {SERVICES.map((s) => (
            <div key={s.name} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className="text-white/90 font-medium">
                    {s.name}
                  </span>
                  <span className="ml-2 text-xs text-white/40">
                    {s.tier}
                  </span>
                </div>
                <StatusBadge status={s.status} />
              </div>
              <div className="flex items-center gap-6 text-sm text-white/60">
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" /> {s.latency}
                </span>
                <span>Uptime: {s.uptime}</span>
                <span
                  className={
                    s.errors > 0
                      ? "text-yellow-400"
                      : "text-emerald-400"
                  }
                >
                  {s.errors} errors
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "degradation" && (
        <div className="space-y-3">
          {DEGRADATION_EVENTS.map((d) => (
            <div key={d.id} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className="font-mono text-xs text-cyan-400">
                    {d.id}
                  </span>
                  <span className="ml-2 text-white/90 font-medium">
                    {d.service}
                  </span>
                </div>
                <StatusBadge status={d.impact} />
              </div>
              <p className="text-white/70 text-sm">{d.type}</p>
              <div className="flex items-center gap-4 mt-2 text-xs text-white/50">
                <span>Started: {d.started}</span>
                <span>Duration: {d.duration}</span>
              </div>
              <p className="text-xs text-emerald-400/70 mt-1">
                {d.action}
              </p>
            </div>
          ))}
        </div>
      )}
      {tab === "metrics" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Health Trends</h3>
          {[
            { m: "Overall Uptime", v: "99.94%", t: "+0.02%" },
            { m: "MTTR", v: "4.2 min", t: "-1.3 min" },
            { m: "MTTD", v: "45 sec", t: "-12 sec" },
            {
              m: "Auto-Remediated",
              v: "78%",
              t: "+5% vs last week",
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
