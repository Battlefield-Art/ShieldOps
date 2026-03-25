import { useState } from "react";
import {
  Key,
  Shield,
  RefreshCw,
  AlertTriangle,
  Clock,
  CheckCircle,
  XCircle,
  Trash2,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type TabId = "overview" | "credentials" | "rotations" | "jit";
type PostureRating = "excellent" | "good" | "fair" | "poor" | "critical";

interface CredentialEntry {
  id: string;
  name: string;
  type: string;
  owner: string;
  posture: PostureRating;
  lastRotated: string;
  daysStale: number;
  scope: string;
  autoRotatable: boolean;
}

// ── Mock Data ────────────────────────────────────────────────────────
const CREDENTIALS: CredentialEntry[] = [
  { id: "cred-001", name: "prod-api-key-main", type: "API Key", owner: "svc-backend", posture: "critical", lastRotated: "142 days ago", daysStale: 142, scope: "read/write/admin", autoRotatable: true },
  { id: "cred-002", name: "oauth-github-ci", type: "OAuth Token", owner: "ci-pipeline", posture: "poor", lastRotated: "93 days ago", daysStale: 93, scope: "repo/packages", autoRotatable: true },
  { id: "cred-003", name: "k8s-deployer-sa", type: "Service Account", owner: "platform-team", posture: "good", lastRotated: "12 days ago", daysStale: 12, scope: "deploy/read", autoRotatable: true },
  { id: "cred-004", name: "stripe-webhook-key", type: "API Key", owner: "billing-svc", posture: "excellent", lastRotated: "3 days ago", daysStale: 3, scope: "webhooks", autoRotatable: false },
  { id: "cred-005", name: "ssh-bastion-root", type: "SSH Key", owner: "infra-team", posture: "poor", lastRotated: "200 days ago", daysStale: 200, scope: "root", autoRotatable: false },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "credentials", label: "Credential Inventory" },
  { id: "rotations", label: "Rotation Status" },
  { id: "jit", label: "JIT Credentials" },
];

const POSTURE_STYLES: Record<PostureRating, string> = {
  excellent: "text-emerald-400",
  good: "text-cyan-400",
  fair: "text-yellow-400",
  poor: "text-orange-400",
  critical: "text-red-400",
};

// ── Component ────────────────────────────────────────────────────────
export default function CredentialLifecycle() {
  const [tab, setTab] = useState<TabId>("overview");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Credential Lifecycle"
        subtitle="JIT credential issuance, rotation scheduling, and stale credential revocation for AI agents"
        icon={<Key className="h-6 w-6" />}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Credentials" value="127" icon={<Key className="h-5 w-5" />} />
        <MetricCard title="Stale / Overdue" value="14" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="JIT Issued (24h)" value="38" icon={<Clock className="h-5 w-5" />} />
        <MetricCard title="Auto-Rotated (7d)" value="22" icon={<RefreshCw className="h-5 w-5" />} />
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
          <h3 className="section-heading">Posture Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="card-interactive p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-medium text-white/90">Posture Score</span>
              </div>
              <p className="text-2xl font-bold text-white">72%</p>
              <p className="text-xs text-white/50 mt-1">14 credentials need attention</p>
            </div>
            <div className="card-interactive p-4">
              <div className="flex items-center gap-2 mb-2">
                <RefreshCw className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-medium text-white/90">Rotation Compliance</span>
              </div>
              <p className="text-2xl font-bold text-white">89%</p>
              <p className="text-xs text-white/50 mt-1">On schedule</p>
            </div>
            <div className="card-interactive p-4">
              <div className="flex items-center gap-2 mb-2">
                <Trash2 className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-medium text-white/90">Revoked (30d)</span>
              </div>
              <p className="text-2xl font-bold text-white">7</p>
              <p className="text-xs text-white/50 mt-1">Stale credentials removed</p>
            </div>
          </div>
        </div>
      )}

      {tab === "credentials" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-white/50">
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Owner</th>
                <th className="px-4 py-3">Posture</th>
                <th className="px-4 py-3">Last Rotated</th>
                <th className="px-4 py-3">Scope</th>
                <th className="px-4 py-3">Auto-Rotate</th>
              </tr>
            </thead>
            <tbody>
              {CREDENTIALS.map((c) => (
                <tr key={c.id} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-white/90 font-medium">{c.name}</td>
                  <td className="px-4 py-3 text-white/70">{c.type}</td>
                  <td className="px-4 py-3 text-white/70">{c.owner}</td>
                  <td className={clsx("px-4 py-3 capitalize font-medium", POSTURE_STYLES[c.posture])}>{c.posture}</td>
                  <td className="px-4 py-3 text-white/50">{c.lastRotated}</td>
                  <td className="px-4 py-3 font-mono text-xs text-white/60">{c.scope}</td>
                  <td className="px-4 py-3">
                    {c.autoRotatable ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-white/30" />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "rotations" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Rotation Schedule</h3>
          {[
            { policy: "Daily", onSchedule: 8, overdue: 0 },
            { policy: "Weekly", onSchedule: 23, overdue: 2 },
            { policy: "Monthly", onSchedule: 54, overdue: 7 },
            { policy: "Quarterly", onSchedule: 31, overdue: 5 },
          ].map((r) => (
            <div key={r.policy} className="card-interactive p-4 flex items-center justify-between">
              <div>
                <p className="text-white/90 font-medium">{r.policy} Rotation</p>
                <p className="text-xs text-white/50">{r.onSchedule} on schedule, {r.overdue} overdue</p>
              </div>
              <StatusBadge status={r.overdue > 0 ? "warning" : "active"} />
            </div>
          ))}
        </div>
      )}

      {tab === "jit" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Recent JIT Credential Issuances</h3>
          <div className="space-y-3">
            {[
              { requester: "soc-investigation-agent", type: "API Key", scope: "read-only", ttl: "15 min", when: "3 min ago" },
              { requester: "remediation-agent", type: "Service Account", scope: "deploy", ttl: "30 min", when: "12 min ago" },
              { requester: "compliance-scanner", type: "OAuth Token", scope: "audit-read", ttl: "60 min", when: "28 min ago" },
            ].map((j, i) => (
              <div key={i} className="card-interactive p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white/90 font-medium">{j.requester}</p>
                    <p className="text-xs text-white/50">{j.type} | Scope: {j.scope} | TTL: {j.ttl}</p>
                  </div>
                  <span className="text-xs text-white/40">{j.when}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
