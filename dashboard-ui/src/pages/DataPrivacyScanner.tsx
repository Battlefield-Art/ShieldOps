import { useState } from "react";
import { Database, Eye, Shield, AlertTriangle, Lock, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "data_catalog" | "pii_findings" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "data_catalog", label: "Data Catalog" },
  { id: "pii_findings", label: "PII Findings" },
  { id: "metrics", label: "Metrics" },
];

const DATASTORES = [
  { id: "DS-001", name: "prod-users-db", type: "PostgreSQL", provider: "AWS RDS", pii: 14, encrypted: true, risk: "high" },
  { id: "DS-002", name: "analytics-lake", type: "S3 Bucket", provider: "AWS S3", pii: 8, encrypted: true, risk: "medium" },
  { id: "DS-003", name: "patient-records", type: "MongoDB", provider: "GCP Atlas", pii: 23, encrypted: true, risk: "critical" },
  { id: "DS-004", name: "payment-cache", type: "Redis", provider: "Azure Cache", pii: 3, encrypted: false, risk: "critical" },
];

const FINDINGS = [
  { id: "PF-001", datastore: "DS-003", field: "patient_ssn", type: "SSN", category: "PHI", masked: false, severity: "critical" },
  { id: "PF-002", datastore: "DS-004", field: "card_number", type: "Credit Card", category: "PCI", masked: false, severity: "critical" },
  { id: "PF-003", datastore: "DS-001", field: "email_address", type: "Email", category: "PII", masked: true, severity: "medium" },
  { id: "PF-004", datastore: "DS-002", field: "ip_address", type: "IP Address", category: "PII", masked: false, severity: "high" },
];

export default function DataPrivacyScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Data Privacy Scanner" subtitle="PII/PHI/PCI data discovery and classification" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Datastores Scanned" value="32" icon={<Database className="h-5 w-5" />} />
        <MetricCard title="PII Findings" value="156" icon={<Eye className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Compliance Score" value="74%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Unmasked Fields" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Data Categories</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "PII", v: "89", c: "text-cyan-400" }, { l: "PHI", v: "34", c: "text-red-400" }, { l: "PCI", v: "18", c: "text-yellow-400" }, { l: "Confidential", v: "15", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "data_catalog" && (<div className="space-y-3">{DATASTORES.map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="ml-2 text-xs text-white/40">{d.provider}</span></div><StatusBadge status={d.risk} /></div><p className="text-white/90 text-sm font-medium">{d.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Type: {d.type}</span><span className={d.pii > 10 ? "text-yellow-400" : "text-white/40"}>{d.pii} PII fields</span><span>{d.encrypted ? <Lock className="h-3 w-3 inline text-emerald-400" /> : <AlertTriangle className="h-3 w-3 inline text-red-400" />} {d.encrypted ? "Encrypted" : "Unencrypted"}</span></div></div>))}</div>)}
      {tab === "pii_findings" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-xs text-white/40">{f.datastore}</span></div><StatusBadge status={f.severity} /></div><p className="text-white/90 text-sm"><span className="font-mono text-cyan-400">{f.field}</span> — {f.type}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className="text-cyan-400">{f.category}</span><span className={f.masked ? "text-emerald-400" : "text-red-400"}>{f.masked ? "Masked" : "Unmasked"}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Privacy Scan Performance</h3>{[{ m: "Scan Coverage", v: "94%", t: "+6%" }, { m: "Classification Accuracy", v: "96%", t: "+2%" }, { m: "Cross-Border Flows", v: "7", t: "-2" }, { m: "GDPR Compliance", v: "82%", t: "+8%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
