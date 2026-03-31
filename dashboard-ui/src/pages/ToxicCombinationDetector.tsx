import { useState } from "react";
import { ShieldOff, Users, AlertTriangle, Target, Zap, Shield } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "toxic_combos" | "blast_radius" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "toxic_combos", label: "Toxic Combos" },
  { id: "blast_radius", label: "Blast Radius" },
  { id: "metrics", label: "Metrics" },
];

const COMBOS = [
  { id: "TC-001", identity: "deploy-svc-account", perms: "s3:PutBucketPolicy + iam:PassRole", type: "Privilege Escalation", severity: "critical", provider: "AWS" },
  { id: "TC-002", identity: "ci-pipeline-role", perms: "sts:AssumeRole + ec2:RunInstances + iam:CreateRole", type: "Lateral Movement", severity: "critical", provider: "AWS" },
  { id: "TC-003", identity: "data-analyst@corp", perms: "storage.objects.get + iam.serviceAccounts.actAs", type: "Data Exfiltration", severity: "high", provider: "GCP" },
  { id: "TC-004", identity: "backup-operator", perms: "Contributor + Key Vault Crypto Officer", type: "SoD Violation", severity: "high", provider: "Azure" },
  { id: "TC-005", identity: "lambda-exec-role", perms: "lambda:CreateFunction + iam:PassRole + s3:GetObject", type: "Supply Chain", severity: "medium", provider: "AWS" },
];

const BLAST = [
  { id: "BR-001", toxic: "TC-001", score: 9.2, resources: 47, identities: 12, data: "S3 prod buckets, RDS snapshots" },
  { id: "BR-002", toxic: "TC-002", score: 8.7, resources: 31, identities: 8, data: "EC2 instances, EBS volumes" },
  { id: "BR-003", toxic: "TC-003", score: 7.1, resources: 15, identities: 3, data: "BigQuery datasets, GCS buckets" },
  { id: "BR-004", toxic: "TC-004", score: 6.5, resources: 9, identities: 2, data: "Key Vault secrets, Blob storage" },
];

export default function ToxicCombinationDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Toxic Combination Detector" subtitle="Cross-cloud toxic permission combination detection and SoD analysis" icon={<ShieldOff className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Identities Scanned" value="2,841" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Toxic Combos" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Max Blast Radius" value="9.2" icon={<Target className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="SoD Violations" value="7" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Violations by Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Privilege Escalation", v: "8", c: "text-red-400" }, { l: "Data Exfiltration", v: "6", c: "text-yellow-400" }, { l: "Lateral Movement", v: "5", c: "text-cyan-400" }, { l: "SoD Violations", v: "4", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "toxic_combos" && (<div className="space-y-3">{COMBOS.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-xs text-white/40">{c.provider}</span></div><StatusBadge status={c.severity} /></div><p className="text-white/90 text-sm font-medium">{c.identity}</p><p className="text-white/60 text-xs mt-1 font-mono">{c.perms}</p><span className="text-xs text-white/50 mt-1 inline-block">{c.type}</span></div>))}</div>)}
      {tab === "blast_radius" && (<div className="space-y-3">{BLAST.map((b) => (<div key={b.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{b.id}</span><span className="ml-2 text-xs text-white/40">from {b.toxic}</span></div><span className={clsx("text-sm font-mono font-bold", b.score >= 8 ? "text-red-400" : b.score >= 6 ? "text-yellow-400" : "text-emerald-400")}>{b.score}</span></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{b.resources} resources</span><span>{b.identities} identities</span></div><p className="text-xs text-white/40 mt-1">Data: {b.data}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detection Performance</h3>{[{ m: "Scan Frequency", v: "Every 4h", t: "Continuous" }, { m: "Detection Accuracy", v: "94%", t: "+3%" }, { m: "Avg Remediation Time", v: "2.1 days", t: "-0.5 days" }, { m: "SoD Compliance", v: "91%", t: "+4%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
