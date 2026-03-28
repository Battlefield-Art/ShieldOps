import { useState } from "react";
import {
  ShieldCheck,
  BarChart3,
  AlertTriangle,
  FileText,
  TrendingUp,
  TrendingDown,
  Minus,
  CheckCircle2,
  XCircle,
  ChevronRight,
} from "lucide-react";

type TabId = "overview" | "policies" | "risk" | "executive";

const TABS: { id: TabId; label: string; icon: typeof ShieldCheck }[] = [
  { id: "overview", label: "Overview", icon: BarChart3 },
  { id: "policies", label: "Policy Adherence", icon: ShieldCheck },
  { id: "risk", label: "Risk Posture", icon: AlertTriangle },
  { id: "executive", label: "Executive Report", icon: FileText },
];

const POSTURE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  strong: { bg: "bg-emerald-500/10", text: "text-emerald-400", label: "Strong" },
  adequate: { bg: "bg-blue-500/10", text: "text-blue-400", label: "Adequate" },
  needs_improvement: { bg: "bg-amber-500/10", text: "text-amber-400", label: "Needs Improvement" },
  weak: { bg: "bg-orange-500/10", text: "text-orange-400", label: "Weak" },
  critical: { bg: "bg-red-500/10", text: "text-red-400", label: "Critical" },
};

const DEMO_DOMAINS = [
  {
    domain: "Access Control",
    adherence: 87.7,
    passing: 2,
    total: 3,
    posture: "adequate",
    trend: "up",
    gaps: ["RBAC coverage: 82.0% vs target 90.0%"],
  },
  {
    domain: "Data Protection",
    adherence: 33.3,
    passing: 1,
    total: 3,
    posture: "critical",
    trend: "down",
    gaps: [
      "DLP policy coverage: 76.0% vs target 90.0%",
      "Data classification: 68.0% vs target 85.0%",
    ],
  },
  {
    domain: "Incident Response",
    adherence: 0.0,
    passing: 0,
    total: 3,
    posture: "critical",
    trend: "down",
    gaps: [
      "MTTR: 6.2hrs vs target 4.0hrs",
      "Runbook coverage: 78.0% vs target 90.0%",
      "Drill frequency: 2 vs target 4 per quarter",
    ],
  },
  {
    domain: "Change Management",
    adherence: 66.7,
    passing: 2,
    total: 3,
    posture: "needs_improvement",
    trend: "stable",
    gaps: ["Rollback readiness: 88.0% vs target 95.0%"],
  },
  {
    domain: "Vendor Risk",
    adherence: 0.0,
    passing: 0,
    total: 3,
    posture: "critical",
    trend: "down",
    gaps: [
      "Vendor assessments: 82.0% vs target 100.0%",
      "Critical vendor SLA: 90.0% vs target 95.0%",
      "Fourth-party risk: 55.0% vs target 80.0%",
    ],
  },
  {
    domain: "Business Continuity",
    adherence: 0.0,
    passing: 0,
    total: 3,
    posture: "weak",
    trend: "stable",
    gaps: [
      "BCP test coverage: 72.0% vs target 90.0%",
      "RTO compliance: 85.0% vs target 95.0%",
      "DR site readiness: 90.0% vs target 100.0%",
    ],
  },
];

const DEMO_INSIGHTS = [
  "Data Protection adherence at 33.3% -- below threshold",
  "Incident Response has 3 control gaps requiring immediate action",
  "Vendor Risk domain has 0% control pass rate -- critical priority",
  "Change Management trending stable but below 75% target",
  "Access Control is the strongest domain at 87.7% adherence",
];

const TrendIcon = ({ trend }: { trend: string }) => {
  if (trend === "up") return <TrendingUp className="h-3.5 w-3.5 text-emerald-400" />;
  if (trend === "down") return <TrendingDown className="h-3.5 w-3.5 text-red-400" />;
  return <Minus className="h-3.5 w-3.5 text-gray-500" />;
};

export default function GovernanceDashboard() {
  const [tab, setTab] = useState<TabId>("overview");

  const avgAdherence =
    DEMO_DOMAINS.reduce((acc, d) => acc + d.adherence, 0) / DEMO_DOMAINS.length;
  const totalPassing = DEMO_DOMAINS.reduce((acc, d) => acc + d.passing, 0);
  const totalControls = DEMO_DOMAINS.reduce((acc, d) => acc + d.total, 0);
  const criticalCount = DEMO_DOMAINS.filter((d) => d.posture === "critical").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <ShieldCheck className="h-6 w-6 text-brand-400" />
          <h1 className="text-xl font-bold text-white">Governance Dashboard</h1>
        </div>
        <p className="text-sm text-gray-400">
          Unified governance metrics, policy adherence tracking, and executive reporting
        </p>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
          <p className="text-xs text-gray-500 mb-1">Overall Adherence</p>
          <p className="text-2xl font-bold text-white">{avgAdherence.toFixed(1)}%</p>
          <p className="text-xs text-gray-500 mt-1">Across {DEMO_DOMAINS.length} domains</p>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
          <p className="text-xs text-gray-500 mb-1">Controls Passing</p>
          <p className="text-2xl font-bold text-white">
            {totalPassing}/{totalControls}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            {((totalPassing / totalControls) * 100).toFixed(0)}% pass rate
          </p>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
          <p className="text-xs text-gray-500 mb-1">Critical Domains</p>
          <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
          <p className="text-xs text-gray-500 mt-1">Require immediate attention</p>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
          <p className="text-xs text-gray-500 mb-1">Overall Posture</p>
          <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-1 text-sm font-semibold text-amber-400">
            Needs Improvement
          </span>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex items-center gap-1 rounded-lg bg-surface-1 p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 rounded-md px-3 py-2 text-xs font-medium transition-colors ${
              tab === t.id
                ? "bg-surface-3 text-white"
                : "text-gray-500 hover:text-gray-300"
            }`}
          >
            <t.icon className="h-3.5 w-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* Overview tab */}
      {tab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Domain summary */}
          <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
            <h3 className="text-sm font-semibold text-gray-200 mb-4">Domain Summary</h3>
            <div className="space-y-3">
              {DEMO_DOMAINS.map((d) => {
                const ps = POSTURE_STYLES[d.posture] ?? POSTURE_STYLES.adequate;
                return (
                  <div
                    key={d.domain}
                    className="flex items-center justify-between rounded-lg border border-white/[0.04] bg-surface-2/30 px-3 py-2.5"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <TrendIcon trend={d.trend} />
                      <div>
                        <p className="text-sm font-medium text-gray-200">{d.domain}</p>
                        <p className="text-xs text-gray-500">
                          {d.passing}/{d.total} controls passing
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-mono text-gray-300">
                        {d.adherence.toFixed(1)}%
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${ps.bg} ${ps.text}`}
                      >
                        {ps.label}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Key insights */}
          <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
            <h3 className="text-sm font-semibold text-gray-200 mb-4">Key Insights</h3>
            <div className="space-y-2">
              {DEMO_INSIGHTS.map((insight, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2.5 rounded-lg border border-white/[0.04] bg-surface-2/30 px-3 py-2.5"
                >
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-400 mt-0.5 shrink-0" />
                  <p className="text-sm text-gray-300">{insight}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Policies tab */}
      {tab === "policies" && (
        <div className="space-y-4">
          {DEMO_DOMAINS.map((d) => (
            <div
              key={d.domain}
              className="rounded-xl border border-white/[0.06] bg-surface-1 p-4"
            >
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-gray-200">{d.domain}</h3>
                <span className="text-sm font-mono text-gray-300">
                  {d.adherence.toFixed(1)}% adherence
                </span>
              </div>
              {/* Progress bar */}
              <div className="h-2 rounded-full bg-surface-3 mb-3">
                <div
                  className={`h-full rounded-full transition-all ${
                    d.adherence >= 75
                      ? "bg-emerald-500"
                      : d.adherence >= 50
                        ? "bg-amber-500"
                        : "bg-red-500"
                  }`}
                  style={{ width: `${Math.min(d.adherence, 100)}%` }}
                />
              </div>
              {/* Controls */}
              <div className="flex items-center gap-4 mb-3 text-xs text-gray-500">
                <span className="flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                  {d.passing} passing
                </span>
                <span className="flex items-center gap-1">
                  <XCircle className="h-3 w-3 text-red-400" />
                  {d.total - d.passing} failing
                </span>
              </div>
              {/* Gaps */}
              {d.gaps.length > 0 && (
                <div className="space-y-1">
                  {d.gaps.map((gap, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 text-xs text-gray-400"
                    >
                      <ChevronRight className="h-3 w-3 text-gray-600" />
                      {gap}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Risk tab */}
      {tab === "risk" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {DEMO_DOMAINS.map((d) => {
            const ps = POSTURE_STYLES[d.posture] ?? POSTURE_STYLES.adequate;
            return (
              <div
                key={d.domain}
                className={`rounded-xl border p-4 ${ps.bg} border-white/[0.06]`}
              >
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-gray-200">{d.domain}</h3>
                  <TrendIcon trend={d.trend} />
                </div>
                <div className="text-3xl font-bold text-white mb-1">
                  {d.adherence.toFixed(0)}
                </div>
                <span
                  className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-medium ${ps.bg} ${ps.text}`}
                >
                  {ps.label}
                </span>
                {d.gaps.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-white/[0.06]">
                    <p className="text-xs text-gray-500 mb-1">
                      {d.gaps.length} risk factor{d.gaps.length > 1 ? "s" : ""}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Executive tab */}
      {tab === "executive" && (
        <div className="space-y-6">
          <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-6">
            <h3 className="text-sm font-semibold text-gray-200 mb-4">Executive Summary</h3>
            <p className="text-sm text-gray-300 leading-relaxed">
              Governance Posture: NEEDS IMPROVEMENT. Across {DEMO_DOMAINS.length} domains,{" "}
              {totalPassing}/{totalControls} controls passing ({avgAdherence.toFixed(1)}% avg
              adherence). {criticalCount} domains in critical state require immediate
              executive attention. Vendor Risk and Incident Response are the highest-priority
              remediation targets. Access Control remains the strongest domain.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
              <h3 className="text-sm font-semibold text-gray-200 mb-3">
                Key Metrics for Leadership
              </h3>
              <div className="space-y-2">
                {[
                  { label: "Overall adherence", value: `${avgAdherence.toFixed(1)}%` },
                  { label: "Controls passing", value: `${totalPassing}/${totalControls}` },
                  { label: "Critical domains", value: String(criticalCount) },
                  { label: "Frameworks covered", value: "SOC 2, ISO 27001, NIST CSF" },
                  { label: "Domains assessed", value: String(DEMO_DOMAINS.length) },
                ].map((m) => (
                  <div
                    key={m.label}
                    className="flex items-center justify-between rounded-lg bg-surface-2/30 px-3 py-2"
                  >
                    <span className="text-xs text-gray-400">{m.label}</span>
                    <span className="text-sm font-medium text-white">{m.value}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-white/[0.06] bg-surface-1 p-4">
              <h3 className="text-sm font-semibold text-gray-200 mb-3">
                Recommended Actions
              </h3>
              <div className="space-y-2">
                {[
                  "Prioritize Vendor Risk remediation -- 0% pass rate",
                  "Invest in Incident Response drills and runbook coverage",
                  "Expand Data Protection DLP and classification programs",
                  "Maintain Access Control momentum as a model domain",
                  "Schedule quarterly governance review with C-suite",
                ].map((action, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2.5 rounded-lg bg-surface-2/30 px-3 py-2"
                  >
                    <span className="text-xs font-bold text-brand-400 mt-0.5">
                      {i + 1}.
                    </span>
                    <p className="text-sm text-gray-300">{action}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
