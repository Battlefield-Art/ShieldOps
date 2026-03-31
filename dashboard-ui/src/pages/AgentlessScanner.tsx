import { useState } from "react";
import { ScanSearch, Cloud, ShieldAlert, AlertTriangle, BarChart3, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "cloud_assets" | "findings" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "cloud_assets", label: "Cloud Assets" },
  { id: "findings", label: "Findings" },
  { id: "metrics", label: "Metrics" },
];

const ASSETS = [
  { id: "AST-001", name: "prod-web-cluster", provider: "AWS", type: "EC2", region: "us-east-1", status: "scanned", findings: 3 },
  { id: "AST-002", name: "data-lake-bucket", provider: "AWS", type: "S3", region: "us-east-1", status: "scanned", findings: 5 },
  { id: "AST-003", name: "api-gateway-prod", provider: "GCP", type: "Cloud Run", region: "us-central1", status: "scanning", findings: 0 },
  { id: "AST-004", name: "postgres-primary", provider: "Azure", type: "SQL Database", region: "eastus", status: "scanned", findings: 2 },
  { id: "AST-005", name: "k8s-ingress-ctrl", provider: "AWS", type: "EKS", region: "eu-west-1", status: "scanned", findings: 1 },
];

const FINDINGS = [
  { id: "FND-001", asset: "data-lake-bucket", title: "Public read access enabled on S3 bucket", severity: "critical", category: "Configuration" },
  { id: "FND-002", asset: "prod-web-cluster", title: "Unpatched OpenSSL CVE-2024-0727", severity: "high", category: "Vulnerability" },
  { id: "FND-003", asset: "postgres-primary", title: "Encryption at rest not enabled", severity: "high", category: "Configuration" },
  { id: "FND-004", asset: "data-lake-bucket", title: "No versioning enabled", severity: "medium", category: "Configuration" },
  { id: "FND-005", asset: "k8s-ingress-ctrl", title: "Overly permissive network policy", severity: "medium", category: "Exposure" },
];

export default function AgentlessScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Agentless Scanner" subtitle="API-based cloud security scanning without deploying agents" icon={<ScanSearch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Cloud Assets" value="1,247" icon={<Cloud className="h-5 w-5" />} />
        <MetricCard title="Critical Findings" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Scan Coverage" value="94%" icon={<ShieldAlert className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Config Compliance" value="87%" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Scan Coverage by Provider</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS", v: "834", c: "text-yellow-400", pct: "96%" }, { l: "GCP", v: "289", c: "text-cyan-400", pct: "91%" }, { l: "Azure", v: "124", c: "text-blue-400", pct: "88%" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p><p className="text-xs text-white/40 mt-1">{s.pct} coverage</p></div>))}</div></div>)}
      {tab === "cloud_assets" && (<div className="space-y-3">{ASSETS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.provider} / {a.type}</span></div><StatusBadge status={a.status} /></div><p className="text-white/90 text-sm font-medium">{a.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Region: {a.region}</span><span className={a.findings > 0 ? "text-yellow-400" : "text-white/40"}>{a.findings} findings</span></div></div>))}</div>)}
      {tab === "findings" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-xs text-white/40">{f.asset}</span></div><StatusBadge status={f.severity} /></div><p className="text-white/90 text-sm">{f.title}</p><span className="text-xs text-white/50">{f.category}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scan Performance</h3>{[{ m: "Avg Scan Duration", v: "4.2 min", t: "-1.1 min" }, { m: "Assets per Scan", v: "312", t: "+45" }, { m: "Finding Accuracy", v: "96%", t: "+2%" }, { m: "Config Compliance", v: "87%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
