import { useState } from "react";
import { Tag, Cloud, CheckCircle, AlertTriangle, Server } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "untagged_resources" | "tag_compliance" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "untagged_resources", label: "Untagged Resources" },
  { id: "tag_compliance", label: "Tag Compliance" },
  { id: "metrics", label: "Metrics" },
];

const UNTAGGED = [
  { id: "RES-001", name: "prod-api-server-12", type: "EC2 Instance", provider: "AWS", region: "us-east-1", missing: ["cost-center", "owner"] },
  { id: "RES-002", name: "staging-bucket-logs", type: "S3 Bucket", provider: "AWS", region: "us-west-2", missing: ["environment", "data-class"] },
  { id: "RES-003", name: "gke-cluster-prod", type: "GKE Cluster", provider: "GCP", region: "us-central1", missing: ["team", "cost-center"] },
  { id: "RES-004", name: "vm-analytics-04", type: "Azure VM", provider: "Azure", region: "eastus", missing: ["owner"] },
];

const POLICIES = [
  { policy: "Cost Center Required", compliant: 89, total: 156, status: "partial" },
  { policy: "Owner Tag Required", compliant: 134, total: 156, status: "partial" },
  { policy: "Environment Tag Required", compliant: 152, total: 156, status: "compliant" },
  { policy: "Data Classification Required", compliant: 78, total: 156, status: "non_compliant" },
];

export default function CloudResourceTagger() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Resource Tagger" subtitle="Automated cloud resource tagging and compliance" icon={<Tag className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Resources" value="1,247" icon={<Server className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Untagged" value="38" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Tag Compliance" value="87%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Providers" value="3" icon={<Cloud className="h-5 w-5 text-sky-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Tag Coverage by Provider</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS", v: "92%", c: "text-orange-400" }, { l: "GCP", v: "85%", c: "text-cyan-400" }, { l: "Azure", v: "79%", c: "text-sky-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "untagged_resources" && (<div className="space-y-3">{UNTAGGED.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.provider} / {r.region}</span></div><StatusBadge status="warning" /></div><p className="text-white/90 text-sm font-medium">{r.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{r.type}</span><span className="text-yellow-400">Missing: {r.missing.join(", ")}</span></div></div>))}</div>)}
      {tab === "tag_compliance" && (<div className="space-y-3">{POLICIES.map((p) => (<div key={p.policy} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{p.policy}</span><StatusBadge status={p.status} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{p.compliant}/{p.total} compliant</span><span className={p.compliant / p.total > 0.9 ? "text-emerald-400" : "text-yellow-400"}>{Math.round((p.compliant / p.total) * 100)}%</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Tagging Metrics</h3>{[{ m: "Tag Compliance", v: "87%", t: "+4%" }, { m: "Auto-Tagged (30d)", v: "342", t: "+58" }, { m: "Policy Violations", v: "18", t: "-7" }, { m: "Avg Tag Latency", v: "2.1 min", t: "-0.4 min" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
