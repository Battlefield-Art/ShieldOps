import { useState } from "react";
import {
  Database,
  Shield,
  AlertTriangle,
  Search,
  FileCheck,
  Lock,
  Activity,
  CheckCircle,
  XCircle,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type TabId = "overview" | "poisoning" | "provenance" | "policies";
type ThreatLevel = "critical" | "high" | "medium" | "low";

interface PoisoningFinding {
  id: string;
  source: string;
  sourceType: string;
  poisoningType: string;
  severity: ThreatLevel;
  confidence: number;
  affectedRecords: number;
  description: string;
  timestamp: string;
}

interface ProvenanceRecord {
  id: string;
  artifactName: string;
  artifactType: string;
  origin: string;
  verified: boolean;
  riskLevel: ThreatLevel;
  lastVerified: string;
}

// ── Mock Data ────────────────────────────────────────────────────────
const FINDINGS: PoisoningFinding[] = [
  {
    id: "PSN-001",
    source: "chromadb-prod",
    sourceType: "vector_db",
    poisoningType: "embedding_manipulation",
    severity: "critical",
    confidence: 0.92,
    affectedRecords: 1250,
    description: "Adversarial embeddings detected in production vector store",
    timestamp: "2 min ago",
  },
  {
    id: "PSN-002",
    source: "doc-ingestion-pipeline",
    sourceType: "document_store",
    poisoningType: "document_injection",
    severity: "high",
    confidence: 0.85,
    affectedRecords: 340,
    description: "Injected documents with hidden instructions found in RAG corpus",
    timestamp: "18 min ago",
  },
  {
    id: "PSN-003",
    source: "training-data-s3",
    sourceType: "training_data",
    poisoningType: "backdoor_trigger",
    severity: "medium",
    confidence: 0.71,
    affectedRecords: 89,
    description: "Potential backdoor trigger patterns in fine-tuning dataset",
    timestamp: "1 hr ago",
  },
];

const PROVENANCE: ProvenanceRecord[] = [
  {
    id: "PRV-001",
    artifactName: "claude-3-sonnet-finetune-v2",
    artifactType: "model_weights",
    origin: "anthropic-registry",
    verified: true,
    riskLevel: "low",
    lastVerified: "2 hr ago",
  },
  {
    id: "PRV-002",
    artifactName: "custom-tokenizer-v3",
    artifactType: "tokenizer",
    origin: "internal-registry",
    verified: false,
    riskLevel: "high",
    lastVerified: "14 days ago",
  },
  {
    id: "PRV-003",
    artifactName: "embedding-ada-002",
    artifactType: "embedding",
    origin: "huggingface",
    verified: true,
    riskLevel: "low",
    lastVerified: "6 hr ago",
  },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "poisoning", label: "Poisoning Findings" },
  { id: "provenance", label: "Model Provenance" },
  { id: "policies", label: "Pipeline Policies" },
];

const SEV_STYLES: Record<ThreatLevel, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-emerald-400",
};

// ── Component ────────────────────────────────────────────────────────
export default function DataPipelineSecurity() {
  const [tab, setTab] = useState<TabId>("overview");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Data Pipeline Security"
        subtitle="Protect RAG pipelines, training data, and model registries from poisoning and supply chain attacks"
        icon={<Database className="h-6 w-6" />}
      />

      {/* Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Pipelines Scanned" value="12" icon={<Search className="h-5 w-5" />} />
        <MetricCard title="Poisoning Findings" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Models Verified" value="8 / 11" icon={<FileCheck className="h-5 w-5" />} />
        <MetricCard title="Policies Enforced" value="24" icon={<Lock className="h-5 w-5" />} />
      </div>

      {/* Tabs */}
      <div className="tab-bar">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx("tab-item", tab === t.id && "tab-item-active")}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Pipeline Health Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="card-interactive p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-medium text-white/90">RAG Pipelines</span>
              </div>
              <p className="text-2xl font-bold text-white">5 Healthy</p>
              <p className="text-xs text-white/50 mt-1">1 with warnings</p>
            </div>
            <div className="card-interactive p-4">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-medium text-white/90">Data Flow Anomalies</span>
              </div>
              <p className="text-2xl font-bold text-white">2</p>
              <p className="text-xs text-white/50 mt-1">Last 24 hours</p>
            </div>
            <div className="card-interactive p-4">
              <div className="flex items-center gap-2 mb-2">
                <FileCheck className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-medium text-white/90">Supply Chain Score</span>
              </div>
              <p className="text-2xl font-bold text-white">87%</p>
              <p className="text-xs text-white/50 mt-1">3 unverified artifacts</p>
            </div>
          </div>
        </div>
      )}

      {tab === "poisoning" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-white/50">
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Affected</th>
                <th className="px-4 py-3">When</th>
              </tr>
            </thead>
            <tbody>
              {FINDINGS.map((f) => (
                <tr key={f.id} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 font-mono text-xs text-cyan-400">{f.id}</td>
                  <td className="px-4 py-3 text-white/80">{f.source}</td>
                  <td className="px-4 py-3 text-white/70">{f.poisoningType}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={f.severity} />
                  </td>
                  <td className="px-4 py-3 text-white/80">{(f.confidence * 100).toFixed(0)}%</td>
                  <td className="px-4 py-3 text-white/80">{f.affectedRecords.toLocaleString()}</td>
                  <td className="px-4 py-3 text-white/50">{f.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "provenance" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-white/50">
                <th className="px-4 py-3">Artifact</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Origin</th>
                <th className="px-4 py-3">Verified</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Last Check</th>
              </tr>
            </thead>
            <tbody>
              {PROVENANCE.map((p) => (
                <tr key={p.id} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-white/90 font-medium">{p.artifactName}</td>
                  <td className="px-4 py-3 text-white/70">{p.artifactType}</td>
                  <td className="px-4 py-3 text-white/70">{p.origin}</td>
                  <td className="px-4 py-3">
                    {p.verified ? (
                      <CheckCircle className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-400" />
                    )}
                  </td>
                  <td className={clsx("px-4 py-3 capitalize", SEV_STYLES[p.riskLevel])}>{p.riskLevel}</td>
                  <td className="px-4 py-3 text-white/50">{p.lastVerified}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "policies" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Active Pipeline Security Policies</h3>
          <div className="space-y-3">
            {[
              { name: "Document Validation", desc: "Validate provenance and integrity of all ingested documents", status: "active" },
              { name: "Embedding Integrity", desc: "Check embeddings against known-good baselines for drift", status: "active" },
              { name: "Model Registry Allowlist", desc: "Only allow models from verified registries", status: "active" },
              { name: "RAG Output Filtering", desc: "Filter RAG outputs for injected instructions", status: "active" },
            ].map((p) => (
              <div key={p.name} className="card-interactive p-4 flex items-center justify-between">
                <div>
                  <p className="text-white/90 font-medium">{p.name}</p>
                  <p className="text-xs text-white/50 mt-1">{p.desc}</p>
                </div>
                <StatusBadge status={p.status} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
