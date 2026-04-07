import { useState } from "react";
import { Network, Shield, Activity, Layers, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "network_map" | "segmentation_policies" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "network_map", label: "Network Map" },
  { id: "segmentation_policies", label: "Policies" },
  { id: "metrics", label: "Metrics" },
];

const SEGMENTS = [
  { id: "SEG-001", name: "Production DB Tier", zone: "data-plane", workloads: 12, policies: 34, status: "enforced" },
  { id: "SEG-002", name: "API Gateway Cluster", zone: "dmz", workloads: 8, policies: 21, status: "monitoring" },
  { id: "SEG-003", name: "CI/CD Pipeline", zone: "build-plane", workloads: 6, policies: 15, status: "enforced" },
  { id: "SEG-004", name: "Internal Services Mesh", zone: "service-plane", workloads: 24, policies: 67, status: "monitoring" },
];

const POLICIES = [
  { id: "POL-001", source: "api-gateway", dest: "auth-service", proto: "HTTPS/443", action: "allow", status: "active" },
  { id: "POL-002", source: "worker-nodes", dest: "db-primary", proto: "PostgreSQL/5432", action: "allow", status: "active" },
  { id: "POL-003", source: "unknown-pod", dest: "secrets-vault", proto: "HTTPS/8200", action: "deny", status: "triggered" },
  { id: "POL-004", source: "monitoring", dest: "all-services", proto: "gRPC/9090", action: "allow", status: "active" },
];

export default function NetworkMicrosegmentation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Network Microsegmentation" subtitle="Zero-trust east-west traffic segmentation and policy engine" icon={<Network className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Segments" value="14" icon={<Layers className="h-5 w-5" />} />
        <MetricCard title="Active Policies" value="137" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Blocked Flows (24h)" value="89" icon={<Lock className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Coverage" value="92%" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Segment Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Enforced", v: "8", c: "text-emerald-400" }, { l: "Monitoring", v: "4", c: "text-yellow-400" }, { l: "Pending", v: "2", c: "text-cyan-400" }, { l: "Violations", v: "3", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "network_map" && (<div className="space-y-3">{SEGMENTS.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.zone}</span></div><StatusBadge status={s.status} /></div><p className="text-white/90 text-sm font-medium">{s.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{s.workloads} workloads</span><span>{s.policies} policies</span></div></div>))}</div>)}
      {tab === "segmentation_policies" && (<div className="space-y-3">{POLICIES.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{p.id}</span><StatusBadge status={p.status} /></div><p className="text-white/90 text-sm">{p.source} → {p.dest}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{p.proto}</span><span className={p.action === "deny" ? "text-red-400" : "text-emerald-400"}>{p.action}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Segmentation Metrics</h3>{[{ m: "Policy Coverage", v: "92%", t: "+4%" }, { m: "Lateral Movement Blocked", v: "89", t: "+12" }, { m: "Mean Time to Enforce", v: "4.2 min", t: "-1.1 min" }, { m: "Zero Trust Score", v: "8.4/10", t: "+0.6" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
