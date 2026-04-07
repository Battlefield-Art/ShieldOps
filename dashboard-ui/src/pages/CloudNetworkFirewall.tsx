import { useState } from "react";
import { Shield, Network, AlertTriangle, Lock, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "rules" | "shadows" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "rules", label: "Overpermissive" },
  { id: "shadows", label: "Shadow Rules" },
  { id: "metrics", label: "Metrics" },
];

const RULES = [
  { id: "FW-001", platform: "AWS SG", rule: "sg-prod-api: 0.0.0.0/0 → port 22", severity: "critical", detail: "SSH open to the internet on production security group" },
  { id: "FW-002", platform: "GCP", rule: "allow-all-internal: 0.0.0.0/0 → all ports", severity: "critical", detail: "Default allow-all rule not restricted to VPC CIDR" },
  { id: "FW-003", platform: "Azure NSG", rule: "nsg-web: Any → ports 80,443,8080-8090", severity: "medium", detail: "Unnecessary port range 8080-8090 open" },
  { id: "FW-004", platform: "K8s", rule: "default namespace: no NetworkPolicy", severity: "high", detail: "No network policy — all pod-to-pod traffic allowed" },
];

export default function CloudNetworkFirewall() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Network Firewall" subtitle="Cross-cloud firewall rule analysis and optimization" icon={<Shield className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Rules Analyzed" value="2,847" icon={<Network className="h-5 w-5" />} />
        <MetricCard title="Overpermissive" value="34" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Shadow Rules" value="12" icon={<Lock className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Optimized" value="89" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Firewall Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Compliant", v: "2,801", c: "text-emerald-400" }, { l: "Overpermissive", v: "34", c: "text-red-400" }, { l: "Shadow", v: "12", c: "text-yellow-400" }, { l: "Score", v: "A-", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "rules" && (<div className="space-y-3">{RULES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.platform}</span></div><StatusBadge status={r.severity} /></div><p className="text-white/90 text-sm font-mono">{r.rule}</p><p className="text-white/50 text-xs mt-1">{r.detail}</p></div>))}</div>)}
      {tab === "shadows" && (<div className="card-surface p-6"><h3 className="section-heading">Shadow Rules</h3><p className="text-white/60">12 shadow rules detected — rules that are never hit because broader rules take precedence.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Firewall Trends</h3>{[{ m: "Compliance Score", v: "98.4%", t: "+1.2%" }, { m: "Rules Optimized", v: "89", t: "+23 this month" }, { m: "Shadow Rules", v: "12", t: "-5" }, { m: "Avg Fix Time", v: "1.4 hrs", t: "-0.3 hrs" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
