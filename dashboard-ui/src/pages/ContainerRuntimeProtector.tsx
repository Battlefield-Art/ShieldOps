import { useState } from "react";
import { Container, Shield, AlertTriangle, Eye, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "workloads" | "runtime_alerts" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "workloads", label: "Workloads" },
  { id: "runtime_alerts", label: "Runtime Alerts" },
  { id: "metrics", label: "Metrics" },
];

const WORKLOADS = [
  { name: "api-gateway", namespace: "prod", type: "Deployment", replicas: 3, risk: "low", detail: "Read-only rootfs, non-root, seccomp enforced" },
  { name: "payment-service", namespace: "prod", type: "Deployment", replicas: 2, risk: "medium", detail: "Image drift detected — hash mismatch from registry" },
  { name: "debug-tools", namespace: "staging", type: "DaemonSet", replicas: 8, risk: "critical", detail: "Privileged container, host PID namespace, no seccomp" },
  { name: "ml-training", namespace: "data", type: "Job", replicas: 1, risk: "high", detail: "Anomalous syscalls: ptrace, execve /bin/sh detected" },
  { name: "redis-cache", namespace: "prod", type: "StatefulSet", replicas: 3, risk: "low", detail: "Baseline profile matched, no drift detected" },
];

const ALERTS = [
  { alert: "Container escape attempt — ptrace syscall in ml-training", severity: "critical", workload: "ml-training", action: "Quarantined" },
  { alert: "Image drift — payment-service running unverified image", severity: "high", workload: "payment-service", action: "Alert sent" },
  { alert: "Privileged container — debug-tools with host access", severity: "critical", workload: "debug-tools", action: "Blocked" },
  { alert: "Unexpected outbound — redis-cache connecting to external IP", severity: "medium", workload: "redis-cache", action: "Investigating" },
];

export default function ContainerRuntimeProtector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Container Runtime Protector" subtitle="Runtime container security and workload protection" icon={<Container className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Protected Workloads" value="142" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Runtime Events" value="48,291" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Drifts Detected" value="7" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Blocked Actions" value="4" icon={<Eye className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Workload Security Posture</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Secured", v: "128", c: "text-emerald-400" }, { l: "Drifted", v: "7", c: "text-yellow-400" }, { l: "Privileged", v: "4", c: "text-red-400" }, { l: "Profiling", v: "3", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "workloads" && (<div className="space-y-3">{WORKLOADS.map((w, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{w.name}</span><span className="ml-2 text-xs text-white/40">{w.namespace} / {w.type}</span></div><StatusBadge status={w.risk} /></div><p className="text-white/50 text-sm">{w.detail}</p><span className="text-xs text-white/40">Replicas: {w.replicas}</span></div>))}</div>)}
      {tab === "runtime_alerts" && (<div className="space-y-3">{ALERTS.map((a, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 text-sm">{a.alert}</span><StatusBadge status={a.severity} /></div><div className="flex gap-4 text-xs text-white/40"><span>Workload: {a.workload}</span><span>Action: {a.action}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Protection Metrics</h3>{[{ m: "Container Escape Attempts", v: "2", t: "Both blocked" }, { m: "Image Integrity", v: "95.1%", t: "-1.2% from drift" }, { m: "Seccomp Enforcement", v: "89%", t: "+4% this week" }, { m: "Mean Detection Time", v: "340ms", t: "-60ms improvement" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
