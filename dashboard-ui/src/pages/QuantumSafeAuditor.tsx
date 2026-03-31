import { useState } from "react";
import { Shield, Lock, AlertTriangle, RefreshCw, BarChart3, Dna } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "crypto_inventory" | "migration_plan" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "crypto_inventory", label: "Crypto Inventory" },
  { id: "migration_plan", label: "Migration Plan" },
  { id: "metrics", label: "Metrics" },
];

const CRYPTO_ASSETS = [
  { algorithm: "RSA-2048", usage: "TLS", status: "vulnerable", service: "api-gateway", replacement: "ML-KEM-768" },
  { algorithm: "ECDSA-P256", usage: "Signing", status: "vulnerable", service: "auth-service", replacement: "ML-DSA-65" },
  { algorithm: "AES-256-GCM", usage: "Encryption", status: "quantum_safe", service: "data-store", replacement: "N/A" },
  { algorithm: "Ed25519", usage: "Key Exchange", status: "vulnerable", service: "mesh-proxy", replacement: "ML-DSA-44" },
  { algorithm: "ML-KEM-768", usage: "TLS", status: "quantum_safe", service: "pqc-gateway", replacement: "N/A" },
];

export default function QuantumSafeAuditor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Quantum Safe Auditor" subtitle="Post-quantum cryptography readiness audit and migration planning" icon={<Dna className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Crypto Assets" value="238" icon={<Lock className="h-5 w-5" />} />
        <MetricCard title="Quantum Vulnerable" value="64" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Migration Plans" value="48" icon={<RefreshCw className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="PQC Readiness" value="73%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Algorithm Status Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Quantum Safe", v: "174", c: "text-emerald-400" }, { l: "Hybrid", v: "12", c: "text-cyan-400" }, { l: "Vulnerable", v: "48", c: "text-orange-400" }, { l: "Deprecated", v: "4", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "crypto_inventory" && (<div className="space-y-3">{CRYPTO_ASSETS.map((a) => (<div key={a.algorithm + a.service} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{a.algorithm}</span><span className="ml-2 text-xs text-white/40">{a.usage}</span></div><StatusBadge status={a.status === "quantum_safe" ? "low" : a.status === "vulnerable" ? "high" : "medium"} /></div><div className="flex gap-4 text-sm"><span className="text-white/50">Service: {a.service}</span><span className="text-white/50">Replacement: <span className="text-cyan-400">{a.replacement}</span></span></div></div>))}</div>)}
      {tab === "migration_plan" && (<div className="card-surface p-6"><h3 className="section-heading">Active Migrations</h3><div className="space-y-2">{[{ from: "RSA-2048", to: "ML-KEM-768", progress: 65, status: "in_progress", services: 12 }, { from: "ECDSA-P256", to: "ML-DSA-65", progress: 40, status: "in_progress", services: 8 }, { from: "Ed25519", to: "ML-DSA-44", progress: 15, status: "planning", services: 5 }, { from: "DH-2048", to: "ML-KEM-512", progress: 0, status: "pending", services: 3 }].map((m, i) => (<div key={i} className="card-interactive p-3"><div className="flex items-center justify-between text-sm mb-2"><span className="text-white/70">{m.from} → <span className="text-cyan-400">{m.to}</span></span><div className="flex gap-3"><span className="text-white/40">{m.services} services</span><StatusBadge status={m.status === "in_progress" ? "medium" : m.status === "pending" ? "high" : "low"} /></div></div><div className="w-full h-2 rounded-full bg-white/10"><div className="h-full rounded-full bg-cyan-400 transition-all" style={{ width: `${m.progress}%` }} /></div><span className="text-xs text-white/40">{m.progress}% complete</span></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">PQC Readiness Trends</h3>{[{ m: "Crypto Assets Scanned", v: "238", t: "+15 this month" }, { m: "HNDL Risk Score", v: "32/100", t: "-8 vs last quarter" }, { m: "Migration Velocity", v: "6/week", t: "+2 vs last month" }, { m: "Quantum Readiness", v: "73%", t: "+5% this quarter" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
