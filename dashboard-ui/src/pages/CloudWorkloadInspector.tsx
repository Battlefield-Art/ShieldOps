import { useState } from "react";
import { Server, Shield, AlertTriangle, CheckCircle, BarChart3, Cloud } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "workloads" | "compliance" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "workloads", label: "Workloads" },
  { id: "compliance", label: "Compliance" },
  { id: "metrics", label: "Metrics" },
];

const WORKLOADS = [
  { name: "prod-api-us-east-1", type: "EC2", provider: "AWS", risk: "high", detail: "Public SG, IMDSv1 enabled, unencrypted EBS" },
  { name: "gce-worker-europe", type: "GCE", provider: "GCP", risk: "medium", detail: "Service account with broad permissions" },
  { name: "k8s-payments-pod", type: "K8s Pod", provider: "AWS", risk: "critical", detail: "Privileged container, host network access" },
  { name: "azure-db-westus2", type: "Azure VM", provider: "Azure", risk: "low", detail: "Encrypted, private subnet, MFA enabled" },
  { name: "lambda-etl-processor", type: "Lambda", provider: "AWS", risk: "medium", detail: "Overprivileged IAM role, no VPC config" },
];

export default function CloudWorkloadInspector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Workload Inspector" subtitle="Security posture assessment for cloud workloads" icon={<Cloud className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Workloads" value="1,247" icon={<Server className="h-5 w-5" />} />
        <MetricCard title="Compliant" value="89%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Critical Findings" value="18" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Risk Score" value="6.4/10" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Workload Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "EC2/GCE/VM", v: "542", c: "text-cyan-400" }, { l: "Containers", v: "389", c: "text-blue-400" }, { l: "Serverless", v: "216", c: "text-purple-400" }, { l: "Databases", v: "100", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "workloads" && (<div className="space-y-3">{WORKLOADS.map((w) => (<div key={w.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{w.name}</span><span className="ml-2 text-xs text-white/40">{w.type} / {w.provider}</span></div><StatusBadge status={w.risk} /></div><p className="text-white/50 text-sm">{w.detail}</p></div>))}</div>)}
      {tab === "compliance" && (<div className="card-surface p-6"><h3 className="section-heading">Compliance Frameworks</h3><div className="space-y-2">{[{ fw: "CIS Benchmarks", pass: "92%", status: "high" }, { fw: "NIST 800-53", pass: "87%", status: "medium" }, { fw: "SOC 2 Type II", pass: "94%", status: "high" }, { fw: "PCI DSS", pass: "81%", status: "medium" }].map((f) => (<div key={f.fw} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70">{f.fw}</span><div className="flex gap-3"><span className="text-cyan-400 font-mono">{f.pass}</span><StatusBadge status={f.status} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Inspection Trends</h3>{[{ m: "Workloads Inspected", v: "1,247", t: "+34 this week" }, { m: "Avg Compliance Rate", v: "89%", t: "+3% vs last month" }, { m: "Critical Findings", v: "18", t: "-7" }, { m: "Mean Time to Remediate", v: "2.4h", t: "-0.8h" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
