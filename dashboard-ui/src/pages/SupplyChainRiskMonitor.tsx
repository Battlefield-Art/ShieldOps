import { useState } from "react";
import { Package, AlertTriangle, Shield, Search, BarChart3, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "dependency_risks" | "supply_chain_map" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "dependency_risks", label: "Dependency Risks" },
  { id: "supply_chain_map", label: "Supply Chain Map" },
  { id: "metrics", label: "Metrics" },
];

const RISKS = [
  { id: "SCR-001", package: "event-stream@3.3.6", category: "Maintainer Risk", severity: "critical", ecosystem: "npm", cves: 1 },
  { id: "SCR-002", package: "coluors@1.4.0", category: "Typosquatting", severity: "high", ecosystem: "npm", cves: 0 },
  { id: "SCR-003", package: "requests@2.28.0", category: "Known Vulnerability", severity: "medium", ecosystem: "pypi", cves: 2 },
  { id: "SCR-004", package: "log4j-core@2.14.1", category: "Known Vulnerability", severity: "critical", ecosystem: "maven", cves: 3 },
];

const DEPS = [
  { name: "react", version: "18.2.0", ecosystem: "npm", slsa: "Level 3", maintainers: 12, risk: "low" },
  { name: "fastapi", version: "0.104.1", ecosystem: "pypi", slsa: "Level 2", maintainers: 8, risk: "low" },
  { name: "lodash", version: "4.17.21", ecosystem: "npm", slsa: "Level 1", maintainers: 3, risk: "medium" },
  { name: "spring-boot", version: "3.2.0", ecosystem: "maven", slsa: "Level 3", maintainers: 45, risk: "low" },
];

export default function SupplyChainRiskMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Supply Chain Risk Monitor" subtitle="Software supply chain risk monitoring with SLSA compliance" icon={<Package className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Dependencies" value="1,247" icon={<Search className="h-5 w-5" />} />
        <MetricCard title="Active Risks" value="18" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="SLSA Compliant" value="84%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Mitigated (30d)" value="31" icon={<CheckCircle className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Breakdown</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Typosquatting", v: "3", c: "text-red-400" }, { l: "Maintainer Risk", v: "5", c: "text-yellow-400" }, { l: "Vulnerabilities", v: "8", c: "text-cyan-400" }, { l: "Provenance", v: "2", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "dependency_risks" && (<div className="space-y-3">{RISKS.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.ecosystem}</span></div><StatusBadge status={r.severity} /></div><p className="text-white/90 text-sm font-medium">{r.package}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{r.category}</span>{r.cves > 0 && <span className="text-yellow-400">{r.cves} CVE(s)</span>}</div></div>))}</div>)}
      {tab === "supply_chain_map" && (<div className="space-y-3">{DEPS.map((d) => (<div key={d.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 text-sm font-medium">{d.name}@{d.version}</span><span className="ml-2 text-xs text-white/40">{d.ecosystem}</span></div><StatusBadge status={d.risk} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>SLSA: {d.slsa}</span><span>{d.maintainers} maintainers</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Supply Chain Metrics</h3>{[{ m: "SLSA Compliance Rate", v: "84%", t: "+6%" }, { m: "Avg Risk Resolution", v: "2.1 days", t: "-0.5 days" }, { m: "Typosquat Detections", v: "3", t: "+1" }, { m: "Provenance Coverage", v: "71%", t: "+9%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
