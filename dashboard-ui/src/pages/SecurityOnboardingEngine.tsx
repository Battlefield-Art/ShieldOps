import { useState } from "react";
import { Rocket, Shield, CheckCircle, AlertTriangle, ClipboardList } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "onboarding_queue" | "service_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "onboarding_queue", label: "Onboarding Queue" },
  { id: "service_status", label: "Service Status" },
  { id: "metrics", label: "Metrics" },
];

const QUEUE = [
  { id: "ONB-101", service: "payment-processor-v3", team: "Payments", tier: "Critical", classification: "PII", status: "in_progress", progress: "4/6 stages" },
  { id: "ONB-102", service: "analytics-dashboard", team: "Data Platform", tier: "Standard", classification: "Internal", status: "pending", progress: "0/6 stages" },
  { id: "ONB-103", service: "customer-portal-api", team: "Frontend", tier: "High", classification: "Confidential", status: "in_progress", progress: "3/6 stages" },
  { id: "ONB-104", service: "ml-inference-svc", team: "ML Platform", tier: "High", classification: "Restricted", status: "in_progress", progress: "5/6 stages" },
];

const SERVICES = [
  { name: "payment-processor-v3", tier: "Critical", controls: 24, passed: 22, failed: 2, readiness: "91.7%", status: "warning" },
  { name: "customer-portal-api", tier: "High", controls: 18, passed: 14, failed: 1, readiness: "77.8%", status: "in_progress" },
  { name: "ml-inference-svc", tier: "High", controls: 20, passed: 19, failed: 1, readiness: "95.0%", status: "active" },
  { name: "internal-wiki", tier: "Low", controls: 8, passed: 8, failed: 0, readiness: "100%", status: "completed" },
];

export default function SecurityOnboardingEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Onboarding Engine" subtitle="Automated security onboarding for new services and workloads" icon={<Rocket className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Services Onboarded" value="47" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="In Progress" value="4" icon={<ClipboardList className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Readiness" value="93.2%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Controls Failed" value="6" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Onboarding by Service Tier</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "8", c: "text-red-400" }, { l: "High", v: "16", c: "text-yellow-400" }, { l: "Standard", v: "18", c: "text-cyan-400" }, { l: "Low", v: "5", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "onboarding_queue" && (<div className="space-y-3">{QUEUE.map((q) => (<div key={q.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{q.id}</span><span className="ml-2 text-xs text-white/40">{q.tier}</span></div><StatusBadge status={q.status} /></div><p className="text-white/90 text-sm font-medium">{q.service}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Team: {q.team}</span><span>Data: {q.classification}</span><span>{q.progress}</span></div></div>))}</div>)}
      {tab === "service_status" && (<div className="space-y-3">{SERVICES.map((s) => (<div key={s.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium text-sm">{s.name}</span><span className="ml-2 text-xs text-white/40">{s.tier}</span></div><StatusBadge status={s.status} /></div><div className="flex gap-4 mt-1 text-xs text-white/50"><span>Controls: {s.controls}</span><span className="text-emerald-400">{s.passed} passed</span>{s.failed > 0 && <span className="text-red-400">{s.failed} failed</span>}<span className="text-cyan-400">Readiness: {s.readiness}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Onboarding Performance</h3>{[{ m: "Avg Onboarding Time", v: "2.4 days", t: "-0.6 days" }, { m: "Control Pass Rate", v: "94.8%", t: "+2.3%" }, { m: "Compliance Coverage", v: "97.1%", t: "+1.8%" }, { m: "Post-Onboard Incidents", v: "0.8/svc", t: "-0.3" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
