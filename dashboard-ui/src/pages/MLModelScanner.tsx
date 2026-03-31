import { useState } from "react";
import { Cpu, Shield, AlertTriangle, Eye, Package, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "model_inventory" | "vulnerabilities" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "model_inventory", label: "Model Inventory" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "metrics", label: "Metrics" },
];

const MODELS = [
  { id: "MDL-001", name: "fraud-detector-v3", format: "pickle", registry: "MLflow", risk: "critical", vulns: 3 },
  { id: "MDL-002", name: "sentiment-bert-ft", format: "safetensors", registry: "HuggingFace", risk: "low", vulns: 0 },
  { id: "MDL-003", name: "anomaly-autoencoder", format: "pytorch", registry: "S3", risk: "high", vulns: 2 },
  { id: "MDL-004", name: "text-classifier-prod", format: "onnx", registry: "MLflow", risk: "medium", vulns: 1 },
];

const VULNS = [
  { id: "MV-001", model: "MDL-001", title: "Unsafe pickle deserialization — arbitrary code execution", severity: "critical", type: "Supply Chain" },
  { id: "MV-002", model: "MDL-003", title: "Unsigned model artifact — no provenance chain", severity: "high", type: "Provenance" },
  { id: "MV-003", model: "MDL-001", title: "Training data hash mismatch — potential poisoning", severity: "high", type: "Integrity" },
  { id: "MV-004", model: "MDL-004", title: "Outdated ONNX runtime with known CVE", severity: "medium", type: "Dependency" },
];

export default function MLModelScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="ML Model Scanner" subtitle="Model supply chain security scanning and vulnerability detection" icon={<Cpu className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Models Scanned" value="47" icon={<Package className="h-5 w-5" />} />
        <MetricCard title="Vulnerabilities" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Provenance Verified" value="83%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Backdoor Indicators" value="2" icon={<Eye className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "3", c: "text-red-400" }, { l: "High", v: "5", c: "text-yellow-400" }, { l: "Medium", v: "8", c: "text-cyan-400" }, { l: "Low", v: "31", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "model_inventory" && (<div className="space-y-3">{MODELS.map((m) => (<div key={m.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{m.id}</span><span className="ml-2 text-xs text-white/40">{m.registry}</span></div><StatusBadge status={m.risk} /></div><p className="text-white/90 text-sm font-medium">{m.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Format: {m.format}</span><span className={m.vulns > 0 ? "text-yellow-400" : "text-white/40"}>{m.vulns} vulnerabilities</span></div></div>))}</div>)}
      {tab === "vulnerabilities" && (<div className="space-y-3">{VULNS.map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="ml-2 text-xs text-white/40">{v.model}</span></div><StatusBadge status={v.severity} /></div><p className="text-white/90 text-sm">{v.title}</p><span className="text-xs text-cyan-400">{v.type}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scan Performance</h3>{[{ m: "Avg Scan Duration", v: "2.4 min", t: "-0.3 min" }, { m: "Pickle Models Found", v: "14", t: "+2" }, { m: "Provenance Coverage", v: "83%", t: "+5%" }, { m: "SBOM Completeness", v: "71%", t: "+12%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
