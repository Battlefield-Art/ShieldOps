import { useState } from "react";
import { Shield, Server, AlertTriangle, CheckCircle, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "k8s_resources" | "violations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "k8s_resources", label: "K8s Resources" },
  { id: "violations", label: "Violations" },
  { id: "metrics", label: "Metrics" },
];

const RESOURCES = [
  { id: "RSC-001", kind: "Deployment", namespace: "production", name: "api-gateway", policies: 12, violations: 0, status: "compliant" },
  { id: "RSC-002", kind: "Pod", namespace: "staging", name: "worker-batch-7x", policies: 8, violations: 3, status: "non-compliant" },
  { id: "RSC-003", kind: "NetworkPolicy", namespace: "default", name: "allow-all-ingress", policies: 5, violations: 2, status: "non-compliant" },
  { id: "RSC-004", kind: "ClusterRole", namespace: "kube-system", name: "admin-override", policies: 6, violations: 1, status: "warning" },
];

const VIOLATIONS = [
  { id: "VIO-001", resource: "worker-batch-7x", severity: "critical", policy: "PSS Restricted", message: "Container running as root" },
  { id: "VIO-002", resource: "allow-all-ingress", severity: "high", policy: "Network Isolation", message: "Unrestricted ingress from all namespaces" },
  { id: "VIO-003", resource: "admin-override", severity: "medium", policy: "RBAC Least Privilege", message: "ClusterRole grants wildcard permissions" },
];

export default function KubernetesPolicyEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Kubernetes Policy Engine" subtitle="Admission control and policy enforcement for K8s clusters" icon={<Shield className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Resources Scanned" value="847" icon={<Server className="h-5 w-5" />} />
        <MetricCard title="Policy Violations" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Compliance Score" value="94.2%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Policies Enforced" value="56" icon={<Lock className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Policy Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Pod Security", v: "98%", c: "text-emerald-400" }, { l: "Network Policy", v: "87%", c: "text-cyan-400" }, { l: "RBAC Audit", v: "92%", c: "text-yellow-400" }, { l: "Admission Control", v: "100%", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "k8s_resources" && (<div className="space-y-3">{RESOURCES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.kind}</span></div><StatusBadge status={r.status} /></div><p className="text-white/90 text-sm">{r.namespace}/{r.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{r.policies} policies</span><span className={r.violations > 0 ? "text-yellow-400" : "text-emerald-400"}>{r.violations} violations</span></div></div>))}</div>)}
      {tab === "violations" && (<div className="space-y-3">{VIOLATIONS.map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="ml-2 text-xs text-white/40">{v.resource}</span></div><StatusBadge status={v.severity} /></div><p className="text-white/90 text-sm">{v.message}</p><span className="text-xs text-cyan-400">{v.policy}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Policy Engine Performance</h3>{[{ m: "Compliance Score", v: "94.2%", t: "+2.1%" }, { m: "Avg Evaluation Time", v: "120ms", t: "-15ms" }, { m: "Auto-Remediated", v: "18", t: "+5" }, { m: "CIS Benchmark Pass", v: "89%", t: "+4%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
