import { useState } from "react";
import { Key, RefreshCw, AlertTriangle, Clock, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "inventory" | "rotations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "inventory", label: "Inventory" },
  { id: "rotations", label: "Rotations" },
  { id: "metrics", label: "Metrics" },
];

const SECRETS = [
  {
    name: "prod-db-postgres",
    type: "Database Credential",
    age: "12 days",
    status: "healthy",
    nextRotation: "18 days",
  },
  {
    name: "stripe-api-key",
    type: "API Key",
    age: "45 days",
    status: "warning",
    nextRotation: "Overdue by 15 days",
  },
  {
    name: "tls-wildcard-cert",
    type: "TLS Certificate",
    age: "89 days",
    status: "healthy",
    nextRotation: "271 days",
  },
  {
    name: "github-deploy-key",
    type: "SSH Key",
    age: "120 days",
    status: "critical",
    nextRotation: "Overdue by 30 days",
  },
  {
    name: "oauth-client-secret",
    type: "OAuth Token",
    age: "7 days",
    status: "healthy",
    nextRotation: "23 days",
  },
];

const ROTATIONS = [
  {
    id: "ROT-001",
    secret: "prod-redis-password",
    status: "completed",
    time: "2h ago",
    method: "Zero-downtime rolling update",
  },
  {
    id: "ROT-002",
    secret: "aws-access-key-svc",
    status: "completed",
    time: "6h ago",
    method: "Dual-key rotation with health check",
  },
  {
    id: "ROT-003",
    secret: "github-deploy-key",
    status: "failed",
    time: "1d ago",
    method: "Rolled back — dependent service failed health check",
  },
  {
    id: "ROT-004",
    secret: "datadog-api-key",
    status: "in_progress",
    time: "Now",
    method: "Coordinated rotation across 3 services",
  },
];

export default function SecretRotationManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader
        title="Secret Rotation Manager"
        subtitle="Automated credential rotation with zero-downtime coordination"
        icon={<Key className="h-6 w-6" />}
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Secrets Tracked"
          value="234"
          icon={<Key className="h-5 w-5" />}
        />
        <MetricCard
          title="Rotated (30d)"
          value="89"
          icon={<RefreshCw className="h-5 w-5 text-emerald-400" />}
        />
        <MetricCard
          title="Overdue"
          value="7"
          icon={<AlertTriangle className="h-5 w-5 text-red-400" />}
        />
        <MetricCard
          title="Success Rate"
          value="97.8%"
          icon={<CheckCircle className="h-5 w-5 text-cyan-400" />}
        />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx("tab-item", tab === t.id && "tab-item-active")}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6">
          <h3 className="section-heading">Secret Health</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { l: "Healthy", v: "220", c: "text-emerald-400" },
              { l: "Warning", v: "7", c: "text-yellow-400" },
              { l: "Overdue", v: "5", c: "text-orange-400" },
              { l: "Critical", v: "2", c: "text-red-400" },
            ].map((s) => (
              <div key={s.l} className="card-interactive p-4 text-center">
                <p className="text-sm text-white/60">{s.l}</p>
                <p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "inventory" && (
        <div className="space-y-3">
          {SECRETS.map((s) => (
            <div key={s.name} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <span className="text-white/90 font-medium">{s.name}</span>
                <StatusBadge status={s.status} />
              </div>
              <div className="flex gap-4 text-sm text-white/50">
                <span>{s.type}</span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" /> Age: {s.age}
                </span>
                <span>Next: {s.nextRotation}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "rotations" && (
        <div className="space-y-3">
          {ROTATIONS.map((r) => (
            <div key={r.id} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className="font-mono text-xs text-cyan-400">{r.id}</span>
                  <span className="ml-2 text-white/90 font-medium">{r.secret}</span>
                </div>
                <StatusBadge status={r.status} />
              </div>
              <p className="text-white/50 text-sm">{r.method}</p>
              <p className="text-xs text-white/40 mt-1">{r.time}</p>
            </div>
          ))}
        </div>
      )}
      {tab === "metrics" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Rotation Performance</h3>
          {[
            { m: "Success Rate", v: "97.8%", t: "+1.2%" },
            { m: "Avg Rotation Time", v: "42 sec", t: "-8 sec" },
            { m: "Zero-Downtime Rate", v: "99.1%", t: "+0.5%" },
            { m: "Rollback Rate", v: "2.2%", t: "-0.8%" },
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
