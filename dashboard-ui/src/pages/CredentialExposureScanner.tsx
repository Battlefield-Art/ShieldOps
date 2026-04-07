import { useState } from "react";
import { Key, AlertTriangle, Activity, Lock, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "detected_leaks" | "rotation_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "detected_leaks", label: "Detected Leaks" },
  { id: "rotation_status", label: "Rotation Status" },
  { id: "metrics", label: "Metrics" },
];

const LEAKS = [
  { id: "CES-001", type: "AWS Access Key", source: "GitHub Public", severity: "critical", detail: "AKIA*** found in config/deploy.yml — active, 72h exposed" },
  { id: "CES-002", type: "SSH Private Key", source: "S3 Bucket", severity: "critical", detail: "RSA key in keys/server.pem — public bucket, lateral movement risk" },
  { id: "CES-003", type: "Anthropic API Key", source: "Jupyter Notebook", severity: "high", detail: "sk-ant-api03-*** in notebooks/test.ipynb — committed 3 days ago" },
  { id: "CES-004", type: "Slack Bot Token", source: "Paste Site", severity: "medium", detail: "xoxb-*** found on pastebin — workspace access, channel history" },
];

export default function CredentialExposureScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Credential Exposure Scanner" subtitle="Credential exposure and leak detection across channels" icon={<Key className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Sources Scanned" value="6" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Credentials Found" value="8" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Rotated" value="5" icon={<RefreshCw className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Active Exposed" value="3" icon={<Lock className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Exposure Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "2", c: "text-red-400" }, { l: "High", v: "3", c: "text-orange-400" }, { l: "Medium", v: "2", c: "text-yellow-400" }, { l: "Low", v: "1", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "detected_leaks" && (<div className="space-y-3">{LEAKS.map((lk) => (<div key={lk.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{lk.id}</span><span className="ml-2 text-white/90 font-medium">{lk.type}</span></div><StatusBadge status={lk.severity} /></div><p className="text-white/70 text-sm">{lk.source}</p><p className="text-white/50 text-xs mt-1">{lk.detail}</p></div>))}</div>)}
      {tab === "rotation_status" && (<div className="card-surface p-6"><p className="text-white/60">Credential rotation tracking: 5 rotated, 2 pending, 1 monitoring. All critical credentials revoked within SLA.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scanner Metrics</h3>{[{ m: "Detection Rate", v: "96.2%", t: "+1.5%" }, { m: "Avg Time to Rotate", v: "18min", t: "-4min" }, { m: "False Positive Rate", v: "3.8%", t: "-0.7%" }, { m: "Sources Coverage", v: "100%", t: "0%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
