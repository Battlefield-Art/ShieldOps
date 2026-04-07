import { useState } from "react";
import { Network, Shield, Lock, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "service_mesh" | "mtls_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "service_mesh", label: "Service Mesh" },
  { id: "mtls_status", label: "mTLS Status" },
  { id: "metrics", label: "Metrics" },
];

const SERVICES = [
  { id: "svc-001", name: "api-gateway", namespace: "production", platform: "Istio", mtls: true, sidecar: true, endpoints: 6 },
  { id: "svc-002", name: "auth-service", namespace: "production", platform: "Istio", mtls: true, sidecar: true, endpoints: 3 },
  { id: "svc-003", name: "payment-processor", namespace: "production", platform: "Istio", mtls: false, sidecar: true, endpoints: 4 },
  { id: "svc-004", name: "legacy-backend", namespace: "default", platform: "Istio", mtls: false, sidecar: false, endpoints: 2 },
  { id: "svc-005", name: "data-pipeline", namespace: "analytics", platform: "Linkerd", mtls: true, sidecar: true, endpoints: 8 },
];

const ANOMALIES = [
  { id: "ANM-001", src: "api-gateway", dst: "legacy-backend", type: "Unauthorized path", severity: "high" },
  { id: "ANM-002", src: "unknown-pod", dst: "payment-processor", type: "Volume spike", severity: "critical" },
  { id: "ANM-003", src: "data-pipeline", dst: "auth-service", type: "Unusual latency", severity: "medium" },
];

export default function SecurityMeshOrchestrator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Mesh Orchestrator" subtitle="Service mesh security orchestration with mTLS enforcement" icon={<Network className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Meshed Services" value="42" icon={<Network className="h-5 w-5" />} />
        <MetricCard title="mTLS Coverage" value="89%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Traffic Anomalies" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Mesh Health" value="94%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Mesh Platforms</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Istio", v: "34", c: "text-cyan-400" }, { l: "Linkerd", v: "6", c: "text-emerald-400" }, { l: "Consul", v: "2", c: "text-yellow-400" }, { l: "Unmeshed", v: "5", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "service_mesh" && (<div className="space-y-3">{SERVICES.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.name}</span><span className="ml-2 text-xs text-white/40">{s.namespace}</span></div><StatusBadge status={s.sidecar ? "active" : "warning"} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Platform: {s.platform}</span><span className={s.mtls ? "text-emerald-400" : "text-red-400"}>mTLS: {s.mtls ? "Enabled" : "Disabled"}</span><span>{s.endpoints} endpoints</span></div></div>))}</div>)}
      {tab === "mtls_status" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.type}</span></div><StatusBadge status={a.severity} /></div><p className="text-white/90 text-sm">{a.src} &rarr; {a.dst}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Mesh Security Metrics</h3>{[{ m: "mTLS Coverage", v: "89%", t: "+4%" }, { m: "Avg Latency Overhead", v: "2.3ms", t: "-0.5ms" }, { m: "Policy Violations (7d)", v: "7", t: "-3" }, { m: "Sidecar Injection Rate", v: "95%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
