import { useState } from "react";
import { KeyRound, Search, AlertTriangle, Shield, FileSearch, Bell } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "secret_findings" | "risk_heatmap" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "secret_findings", label: "Secret Findings" },
  { id: "risk_heatmap", label: "Risk Heatmap" },
  { id: "metrics", label: "Metrics" },
];

const FINDINGS = [
  { id: "SEC-001", type: "API Key", file: "src/config/prod.env", repo: "backend-api", severity: "critical", method: "Regex Pattern", age: "3 days" },
  { id: "SEC-002", type: "Private Key", file: "deploy/tls.key", repo: "infra-charts", severity: "critical", method: "Known Format", age: "12 days" },
  { id: "SEC-003", type: "Connection String", file: "docker-compose.yml", repo: "dev-tools", severity: "high", method: "Entropy Analysis", age: "7 days" },
  { id: "SEC-004", type: "Token", file: ".github/workflows/ci.yml", repo: "frontend-app", severity: "medium", method: "Git History", age: "30 days" },
  { id: "SEC-005", type: "Password", file: "tests/fixtures/seed.sql", repo: "data-pipeline", severity: "low", method: "Regex Pattern", age: "45 days" },
];

const HEATMAP = [
  { repo: "backend-api", critical: 2, high: 3, medium: 1, low: 0 },
  { repo: "infra-charts", critical: 1, high: 1, medium: 2, low: 1 },
  { repo: "dev-tools", critical: 0, high: 2, medium: 3, low: 2 },
  { repo: "frontend-app", critical: 0, high: 0, medium: 1, low: 3 },
  { repo: "data-pipeline", critical: 0, high: 1, medium: 0, low: 2 },
];

export default function SecretSprawlDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Secret Sprawl Detector" subtitle="Credential sprawl detection across repos and config" icon={<KeyRound className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Secrets" value="38" icon={<Search className="h-5 w-5" />} />
        <MetricCard title="Critical" value="5" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Repos Scanned" value="24" icon={<FileSearch className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Alerts Sent" value="12" icon={<Bell className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Secret Types</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "API Keys", v: "14", c: "text-red-400" }, { l: "Tokens", v: "9", c: "text-yellow-400" }, { l: "Passwords", v: "8", c: "text-cyan-400" }, { l: "Certificates", v: "7", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "secret_findings" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-xs text-white/40">{f.type}</span></div><StatusBadge status={f.severity} /></div><p className="text-white/90 text-sm font-mono">{f.file}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{f.repo}</span><span>{f.method}</span><span>Age: {f.age}</span></div></div>))}</div>)}
      {tab === "risk_heatmap" && (<div className="card-surface p-6"><h3 className="section-heading">Repository Risk Heatmap</h3><div className="space-y-2 mt-4">{HEATMAP.map((r) => (<div key={r.repo} className="card-interactive p-4 flex items-center justify-between"><span className="text-white/90 font-mono text-sm">{r.repo}</span><div className="flex gap-3 text-xs">{r.critical > 0 && <span className="text-red-400 font-bold">{r.critical} crit</span>}{r.high > 0 && <span className="text-orange-400">{r.high} high</span>}{r.medium > 0 && <span className="text-yellow-400">{r.medium} med</span>}{r.low > 0 && <span className="text-white/40">{r.low} low</span>}</div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detection Metrics</h3>{[{ m: "Secrets per Repo (avg)", v: "1.6", t: "-0.4" }, { m: "Rotation Compliance", v: "68%", t: "+12%" }, { m: "Mean Time to Rotate", v: "4.2 days", t: "-1.8 days" }, { m: "Pre-commit Block Rate", v: "94%", t: "+3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
