import { useState } from "react";
import {
  Puzzle,
  AlertTriangle,
  Link2,
  FileText,
  Zap,
  Clock,
  ArrowRight,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type TabId = "overview" | "situations" | "correlations" | "metrics";

interface ComposedSituation {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  alertCount: number;
  vendorCount: number;
  killChainPhases: string[];
  status: "active" | "investigating" | "resolved";
  created: string;
}

// ── Mock Data ────────────────────────────────────────────────────────
const SITUATIONS: ComposedSituation[] = [
  {
    id: "SIT-001",
    title: "Lateral movement via OAuth token reuse across AWS + Azure",
    severity: "critical",
    alertCount: 12,
    vendorCount: 3,
    killChainPhases: ["Initial Access", "Lateral Movement", "Collection"],
    status: "active",
    created: "8 min ago",
  },
  {
    id: "SIT-002",
    title: "Prompt injection campaign targeting production RAG pipeline",
    severity: "high",
    alertCount: 7,
    vendorCount: 2,
    killChainPhases: ["Execution", "Exfiltration"],
    status: "investigating",
    created: "42 min ago",
  },
  {
    id: "SIT-003",
    title: "Stale service account used from anomalous geo-location",
    severity: "medium",
    alertCount: 4,
    vendorCount: 2,
    killChainPhases: ["Initial Access", "Persistence"],
    status: "investigating",
    created: "2 hr ago",
  },
  {
    id: "SIT-004",
    title: "Port scan followed by failed SSH brute force on prod-web cluster",
    severity: "medium",
    alertCount: 23,
    vendorCount: 1,
    killChainPhases: ["Reconnaissance", "Initial Access"],
    status: "resolved",
    created: "6 hr ago",
  },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "situations", label: "Composed Situations" },
  { id: "correlations", label: "Correlation Engine" },
  { id: "metrics", label: "Composition Metrics" },
];

// ── Component ────────────────────────────────────────────────────────
export default function SituationComposer() {
  const [tab, setTab] = useState<TabId>("overview");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Situation Composer"
        subtitle="Aggregate alerts from multiple vendors into coherent security situations with kill-chain narratives"
        icon={<Puzzle className="h-6 w-6" />}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Situations" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Alerts Correlated (24h)" value="847" icon={<Link2 className="h-5 w-5" />} />
        <MetricCard title="Alert-to-Situation Ratio" value="47:1" icon={<Zap className="h-5 w-5" />} />
        <MetricCard title="Avg Composition Time" value="2.3s" icon={<Clock className="h-5 w-5" />} />
      </div>

      <div className="tab-bar">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Composition Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Raw Alerts (24h)</p>
              <p className="text-2xl font-bold text-white mt-1">847</p>
              <p className="text-xs text-white/40">From 7 vendor sources</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Situations Created</p>
              <p className="text-2xl font-bold text-cyan-400 mt-1">18</p>
              <p className="text-xs text-white/40">47:1 noise reduction</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Auto-Resolved</p>
              <p className="text-2xl font-bold text-emerald-400 mt-1">11</p>
              <p className="text-xs text-white/40">61% auto-resolution rate</p>
            </div>
          </div>
        </div>
      )}

      {tab === "situations" && (
        <div className="space-y-3">
          {SITUATIONS.map((s) => (
            <div key={s.id} className="card-interactive p-5">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-xs text-cyan-400">{s.id}</span>
                    <StatusBadge status={s.severity} />
                    <StatusBadge status={s.status} />
                  </div>
                  <h4 className="text-white/90 font-medium">{s.title}</h4>
                </div>
                <span className="text-xs text-white/40">{s.created}</span>
              </div>
              <div className="flex items-center gap-4 text-xs text-white/50">
                <span>{s.alertCount} alerts</span>
                <span>{s.vendorCount} vendors</span>
                <div className="flex items-center gap-1">
                  {s.killChainPhases.map((p, i) => (
                    <span key={p} className="flex items-center gap-1">
                      <span className="text-white/60">{p}</span>
                      {i < s.killChainPhases.length - 1 && <ArrowRight className="h-3 w-3 text-white/30" />}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === "correlations" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Correlation Rules</h3>
          <div className="space-y-3">
            {[
              { type: "Shared IP Address", matches: 124, confidence: 92 },
              { type: "Same User Identity", matches: 89, confidence: 88 },
              { type: "Temporal Proximity (<5min)", matches: 67, confidence: 78 },
              { type: "Kill Chain Progression", matches: 34, confidence: 85 },
              { type: "Cross-Vendor Same Asset", matches: 23, confidence: 91 },
            ].map((c) => (
              <div key={c.type} className="card-interactive p-4 flex items-center justify-between">
                <div>
                  <p className="text-white/90 font-medium">{c.type}</p>
                  <p className="text-xs text-white/50">{c.matches} matches (24h) | {c.confidence}% avg confidence</p>
                </div>
                <Link2 className="h-4 w-4 text-cyan-400" />
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "metrics" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Composition Performance</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">MTTD (Detection)</p>
              <p className="text-2xl font-bold text-white mt-1">3.2 min</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">MTTR (Response)</p>
              <p className="text-2xl font-bold text-white mt-1">11.4 min</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Human Clicks/Incident</p>
              <p className="text-2xl font-bold text-emerald-400 mt-1">2.1</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">False Positive Rate</p>
              <p className="text-2xl font-bold text-cyan-400 mt-1">4.2%</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
