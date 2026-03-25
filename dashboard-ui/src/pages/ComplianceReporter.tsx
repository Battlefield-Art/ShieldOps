import { useState } from "react";
import {
  FileCheck,
  Shield,
  Download,
  AlertTriangle,
  CheckCircle,
  XCircle,
  BarChart3,
  Clock,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type TabId = "overview" | "reports" | "controls" | "evidence";

interface ComplianceReport {
  id: string;
  framework: string;
  title: string;
  period: string;
  complianceScore: number;
  totalControls: number;
  compliantControls: number;
  status: "delivered" | "review" | "draft";
  generatedAt: string;
}

// ── Mock Data ────────────────────────────────────────────────────────
const REPORTS: ComplianceReport[] = [
  { id: "rpt-001", framework: "SOC 2 Type II", title: "Annual SOC 2 Type II Report", period: "Jan 2025 – Dec 2025", complianceScore: 94, totalControls: 64, compliantControls: 60, status: "delivered", generatedAt: "3 days ago" },
  { id: "rpt-002", framework: "PCI DSS 4.0", title: "PCI DSS Self-Assessment", period: "Jul 2025 – Dec 2025", complianceScore: 91, totalControls: 42, compliantControls: 38, status: "review", generatedAt: "1 day ago" },
  { id: "rpt-003", framework: "HIPAA", title: "HIPAA Security Assessment", period: "Jan 2025 – Dec 2025", complianceScore: 88, totalControls: 54, compliantControls: 47, status: "draft", generatedAt: "6 hr ago" },
  { id: "rpt-004", framework: "FedRAMP Mod", title: "FedRAMP Moderate Package", period: "Jan 2025 – Dec 2025", complianceScore: 85, totalControls: 325, compliantControls: 276, status: "draft", generatedAt: "12 hr ago" },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "reports", label: "Reports" },
  { id: "controls", label: "Control Assessment" },
  { id: "evidence", label: "Evidence Packages" },
];

// ── Component ────────────────────────────────────────────────────────
export default function ComplianceReporter() {
  const [tab, setTab] = useState<TabId>("overview");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compliance Reporter"
        subtitle="Generate audit-ready compliance reports with automated evidence packaging"
        icon={<FileCheck className="h-6 w-6" />}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Frameworks Tracked" value="4" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Avg Compliance Score" value="89.5%" icon={<BarChart3 className="h-5 w-5" />} />
        <MetricCard title="Reports Generated" value="4" icon={<FileCheck className="h-5 w-5" />} />
        <MetricCard title="Evidence Items" value="1,247" icon={<Download className="h-5 w-5" />} />
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
          <h3 className="section-heading">Compliance Posture</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { fw: "SOC 2", score: 94, color: "text-emerald-400" },
              { fw: "PCI DSS", score: 91, color: "text-emerald-400" },
              { fw: "HIPAA", score: 88, color: "text-cyan-400" },
              { fw: "FedRAMP", score: 85, color: "text-yellow-400" },
            ].map((f) => (
              <div key={f.fw} className="card-interactive p-4 text-center">
                <p className="text-sm text-white/60">{f.fw}</p>
                <p className={clsx("text-3xl font-bold mt-2", f.color)}>{f.score}%</p>
                <div className="h-2 bg-white/10 rounded-full mt-3">
                  <div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${f.score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "reports" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-white/50">
                <th className="px-4 py-3">Framework</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Period</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Controls</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Generated</th>
              </tr>
            </thead>
            <tbody>
              {REPORTS.map((r) => (
                <tr key={r.id} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-cyan-400 font-medium">{r.framework}</td>
                  <td className="px-4 py-3 text-white/90">{r.title}</td>
                  <td className="px-4 py-3 text-white/60 text-xs">{r.period}</td>
                  <td className="px-4 py-3">
                    <span className={clsx("font-bold", r.complianceScore >= 90 ? "text-emerald-400" : r.complianceScore >= 80 ? "text-yellow-400" : "text-red-400")}>
                      {r.complianceScore}%
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white/70">{r.compliantControls}/{r.totalControls}</td>
                  <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
                  <td className="px-4 py-3 text-white/50">{r.generatedAt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "controls" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Control Assessment Summary</h3>
          {[
            { domain: "Access Control", compliant: 18, partial: 2, nonCompliant: 0 },
            { domain: "Change Management", compliant: 12, partial: 1, nonCompliant: 1 },
            { domain: "Risk Assessment", compliant: 8, partial: 2, nonCompliant: 0 },
            { domain: "Incident Response", compliant: 10, partial: 0, nonCompliant: 0 },
            { domain: "Data Protection", compliant: 7, partial: 3, nonCompliant: 1 },
            { domain: "Network Security", compliant: 5, partial: 1, nonCompliant: 0 },
          ].map((d) => (
            <div key={d.domain} className="card-interactive p-4 flex items-center justify-between">
              <div>
                <p className="text-white/90 font-medium">{d.domain}</p>
                <div className="flex items-center gap-3 mt-1 text-xs">
                  <span className="text-emerald-400">{d.compliant} compliant</span>
                  {d.partial > 0 && <span className="text-yellow-400">{d.partial} partial</span>}
                  {d.nonCompliant > 0 && <span className="text-red-400">{d.nonCompliant} non-compliant</span>}
                </div>
              </div>
              {d.nonCompliant > 0 ? (
                <XCircle className="h-4 w-4 text-red-400" />
              ) : d.partial > 0 ? (
                <AlertTriangle className="h-4 w-4 text-yellow-400" />
              ) : (
                <CheckCircle className="h-4 w-4 text-emerald-400" />
              )}
            </div>
          ))}
        </div>
      )}

      {tab === "evidence" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Evidence Package Status</h3>
          <div className="space-y-3">
            {[
              { framework: "SOC 2 Type II", artifacts: 342, size: "2.4 GB", verified: true, lastUpdated: "3 days ago" },
              { framework: "PCI DSS 4.0", artifacts: 186, size: "1.1 GB", verified: true, lastUpdated: "1 day ago" },
              { framework: "HIPAA", artifacts: 428, size: "3.2 GB", verified: false, lastUpdated: "6 hr ago" },
              { framework: "FedRAMP Moderate", artifacts: 291, size: "2.8 GB", verified: false, lastUpdated: "12 hr ago" },
            ].map((e) => (
              <div key={e.framework} className="card-interactive p-4 flex items-center justify-between">
                <div>
                  <p className="text-white/90 font-medium">{e.framework}</p>
                  <p className="text-xs text-white/50">{e.artifacts} artifacts | {e.size} | Updated {e.lastUpdated}</p>
                </div>
                <div className="flex items-center gap-2">
                  {e.verified ? (
                    <span className="text-xs text-emerald-400 flex items-center gap-1"><CheckCircle className="h-3 w-3" /> Verified</span>
                  ) : (
                    <span className="text-xs text-yellow-400 flex items-center gap-1"><Clock className="h-3 w-3" /> Pending</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
