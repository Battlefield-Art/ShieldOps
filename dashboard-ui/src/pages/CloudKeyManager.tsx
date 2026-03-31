import { useState } from "react";
import { Key, Shield, AlertTriangle, Activity, RotateCcw, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "key_inventory" | "rotation_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "key_inventory", label: "Key Inventory" },
  { id: "rotation_status", label: "Rotation Status" },
  { id: "metrics", label: "Metrics" },
];

const KEYS = [
  { id: "CK-001", alias: "prod-data-encryption", provider: "AWS KMS", algorithm: "AES-256", region: "us-east-1", rotationDays: 120, status: "overdue" },
  { id: "CK-002", alias: "staging-secrets", provider: "AWS KMS", algorithm: "AES-256", region: "us-west-2", rotationDays: 45, status: "compliant" },
  { id: "CK-003", alias: "gcp-app-signing", provider: "GCP KMS", algorithm: "RSA-2048", region: "us-central1", rotationDays: 200, status: "critical" },
  { id: "CK-004", alias: "az-tls-cert-key", provider: "Azure Key Vault", algorithm: "RSA-4096", region: "eastus", rotationDays: 180, status: "overdue" },
  { id: "CK-005", alias: "vault-transit-key", provider: "HashiCorp Vault", algorithm: "AES-256-GCM", region: "on-prem", rotationDays: 30, status: "compliant" },
  { id: "CK-006", alias: "legacy-backup-key", provider: "AWS KMS", algorithm: "DES-128", region: "us-east-1", rotationDays: 900, status: "critical" },
];

export default function CloudKeyManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Key Manager" subtitle="Cloud KMS key lifecycle management across AWS, GCP, and Azure" icon={<Key className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Keys" value="847" icon={<Key className="h-5 w-5" />} />
        <MetricCard title="At Risk" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Rotation Compliant" value="92%" icon={<RotateCcw className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Quantum Safe" value="78%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">KMS Health by Provider</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "AWS KMS", v: "412 keys", c: "text-emerald-400" }, { l: "GCP KMS", v: "198 keys", c: "text-cyan-400" }, { l: "Azure Vault", v: "157 keys", c: "text-blue-400" }, { l: "Vault/HSM", v: "80 keys", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "key_inventory" && (<div className="space-y-3">{KEYS.map((k) => (<div key={k.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{k.id}</span><span className="ml-2 text-white/90 font-medium">{k.alias}</span></div><StatusBadge status={k.status} /></div><div className="flex items-center gap-4 text-sm text-white/60"><span>{k.provider}</span><span>{k.algorithm}</span><span>{k.region}</span><span>Rotation: {k.rotationDays}d</span></div></div>))}</div>)}
      {tab === "rotation_status" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Rotation Compliance</h3>{[{ r: "Policy: 90-day max", v: "68%", s: "warning" }, { r: "Auto-rotate enabled", v: "54%", s: "info" }, { r: "Overdue > 180d", v: "12 keys", s: "critical" }, { r: "Quantum-safe algo", v: "78%", s: "healthy" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.r}</p></div><div className="flex items-center gap-3"><span className="text-cyan-400 font-mono">{x.v}</span><StatusBadge status={x.s} /></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Key Management Trends</h3>{[{ m: "Avg Rotation Age", v: "67d", t: "-12d" }, { m: "Crypto Agility", v: "0.74", t: "+0.08" }, { m: "Policy Compliance", v: "92%", t: "+4%" }, { m: "Unused Keys", v: "34", t: "-8" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
