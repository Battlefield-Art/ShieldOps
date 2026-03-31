import { useState } from "react";
import { Network, Globe, Shield, AlertTriangle, BarChart3, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "topology_map" | "security_groups" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "topology_map", label: "Topology Map" },
  { id: "security_groups", label: "Security Groups" },
  { id: "metrics", label: "Metrics" },
];

const VPCS = [
  { id: "vpc-0a1b2c3d", name: "prod-vpc", provider: "AWS", subnets: 12, exposures: 3, status: "warning" },
  { id: "vpc-4e5f6g7h", name: "staging-vpc", provider: "AWS", subnets: 6, exposures: 1, status: "healthy" },
  { id: "vnet-prod-01", name: "prod-vnet", provider: "Azure", subnets: 8, exposures: 2, status: "warning" },
  { id: "vpc-gcp-main", name: "gcp-main", provider: "GCP", subnets: 4, exposures: 0, status: "healthy" },
];

const SECURITY_GROUPS = [
  { id: "sg-001", name: "web-tier-sg", vpc: "prod-vpc", rules: 14, exposure: "high", open_ports: "80, 443, 8080" },
  { id: "sg-002", name: "db-tier-sg", vpc: "prod-vpc", rules: 6, exposure: "low", open_ports: "5432" },
  { id: "sg-003", name: "admin-sg", vpc: "prod-vpc", rules: 22, exposure: "critical", open_ports: "22, 3389, 0.0.0.0/0" },
  { id: "sg-004", name: "api-tier-sg", vpc: "staging-vpc", rules: 8, exposure: "medium", open_ports: "443, 8443" },
];

export default function CloudNetworkAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Network Analyzer" subtitle="Network topology and security analysis across clouds" icon={<Network className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="VPCs/VNets" value="14" icon={<Globe className="h-5 w-5" />} />
        <MetricCard title="Exposures" value="6" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Security Groups" value="87" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Segmentation Score" value="78%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Cloud Providers</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS", v: "8 VPCs", c: "text-yellow-400" }, { l: "Azure", v: "4 VNets", c: "text-cyan-400" }, { l: "GCP", v: "2 VPCs", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "topology_map" && (<div className="space-y-3">{VPCS.map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="ml-2 text-xs text-white/40">{v.provider}</span></div><StatusBadge status={v.status} /></div><p className="text-white/90 text-sm font-medium">{v.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{v.subnets} subnets</span><span className={v.exposures > 0 ? "text-yellow-400" : "text-white/40"}>{v.exposures} exposures</span></div></div>))}</div>)}
      {tab === "security_groups" && (<div className="space-y-3">{SECURITY_GROUPS.map((sg) => (<div key={sg.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{sg.id}</span><span className="ml-2 text-xs text-white/40">{sg.vpc}</span></div><StatusBadge status={sg.exposure} /></div><p className="text-white/90 text-sm font-medium">{sg.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{sg.rules} rules</span><span>Ports: {sg.open_ports}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Network Security Metrics</h3>{[{ m: "Segmentation Score", v: "78%", t: "+4%" }, { m: "Public Exposure", v: "6 resources", t: "-2" }, { m: "Route Anomalies", v: "3", t: "-1" }, { m: "Avg Scan Time", v: "4.2 min", t: "-0.6 min" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
