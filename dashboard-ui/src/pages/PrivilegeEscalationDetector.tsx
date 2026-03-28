import { useState } from "react";
import { Shield, AlertTriangle, Key, Lock, UserX, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "findings" | "risk" | "response";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Escalation Findings" },
  { id: "risk", label: "Risk Assessment" },
  { id: "response", label: "Response Actions" },
];

export default function PrivilegeEscalationDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Privilege Escalation Detector" subtitle="Detect sudo abuse, role changes, IAM modifications, and service account elevation" icon={<Key className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Findings" value="5" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Events Analyzed (24h)" value="8.7K" icon={<Zap className="h-5 w-5" />} />
        <MetricCard title="Critical Escalations" value="2" icon={<UserX className="h-5 w-5 text-red-500" />} />
        <MetricCard title="Auto-Contained" value="3" icon={<Shield className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Escalation Type Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { type: "Sudo Abuse", count: 2, severity: "critical" },
              { type: "IAM Policy Modification", count: 2, severity: "high" },
              { type: "Service Account Elevation", count: 1, severity: "medium" },
            ].map((m) => (
              <div key={m.type} className="card-interactive p-4">
                <div className="flex items-center justify-between mb-2"><span className="text-sm text-white/60">{m.type}</span><StatusBadge status={m.severity} /></div>
                <p className="text-2xl font-bold text-white">{m.count} findings</p>
              </div>
            ))}
          </div>
          <h3 className="section-heading mt-6">MITRE ATT&CK Coverage</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { technique: "T1548.003", name: "Sudo Abuse", count: 2 },
              { technique: "T1098", name: "Account Manipulation", count: 2 },
              { technique: "T1078.004", name: "Cloud Accounts", count: 1 },
              { technique: "T1134.001", name: "Token Impersonation", count: 1 },
            ].map((t) => (
              <div key={t.technique} className="card-interactive p-3">
                <span className="font-mono text-xs text-cyan-400">{t.technique}</span>
                <p className="text-sm text-white/80 mt-1">{t.name}</p>
                <p className="text-lg font-bold text-white">{t.count}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "findings" && (
        <div className="space-y-3">
          {[
            { id: "ESC-001", type: "Sudo Abuse", principal: "dev-user-42", source: "Linux host-prod-3", target: "/usr/bin/passwd", confidence: 94, mitre: "T1548.003", severity: "critical", delta: "user -> root" },
            { id: "ESC-002", type: "IAM Policy Modification", principal: "ci-deploy-sa", source: "AWS", target: "arn:aws:iam::123:policy/AdminAccess", confidence: 88, mitre: "T1098.001", severity: "high", delta: "ReadOnly -> Admin" },
            { id: "ESC-003", type: "Service Account Elevation", principal: "k8s-workload-sa", source: "GCP", target: "sa-admin@project.iam", confidence: 82, mitre: "T1078.004", severity: "high", delta: "viewer -> owner" },
            { id: "ESC-004", type: "Role Change", principal: "intern-user", source: "Azure", target: "/subscriptions/xxx/roleAssignments", confidence: 76, mitre: "T1098", severity: "medium", delta: "Reader -> Contributor" },
            { id: "ESC-005", type: "Privilege Boundary Bypass", principal: "admin-sa", source: "AWS", target: "PermissionBoundary-prod", confidence: 91, mitre: "T1548", severity: "critical", delta: "Bounded -> Unbounded" },
          ].map((f) => (
            <div key={f.id} className="card-interactive p-5">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-xs text-cyan-400">{f.id}</span>
                    <StatusBadge status={f.severity} />
                  </div>
                  <h4 className="text-white/90 font-medium">{f.type}</h4>
                </div>
                <span className="text-xs text-white/40">{f.confidence}% confidence</span>
              </div>
              <div className="flex items-center gap-2 text-sm text-white/60 flex-wrap">
                <Lock className="h-3 w-3 text-cyan-400" />
                <span>{f.principal}</span>
                <span className="text-white/30">|</span>
                <span>{f.source}</span>
                <span className="text-white/30">|</span>
                <span className="font-mono text-xs">{f.delta}</span>
                <span className="text-white/30">|</span>
                <span className="font-mono text-xs text-white/40">{f.mitre}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "risk" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Risk Assessment</h3>
          {[
            { finding: "ESC-001", resources: 8, identities: 3, blastRadius: 11, severity: "critical", actions: ["Lock account", "Audit sudoers", "Escalate to IR"] },
            { finding: "ESC-005", resources: 12, identities: 5, blastRadius: 17, severity: "critical", actions: ["Restore boundary", "Enforce SCP", "Escalate to IR"] },
            { finding: "ESC-002", resources: 6, identities: 2, blastRadius: 8, severity: "high", actions: ["Revert IAM policy", "Enable IAM alerting"] },
          ].map((r) => (
            <div key={r.finding} className="card-interactive p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs text-cyan-400">{r.finding}</span>
                <StatusBadge status={r.severity} />
              </div>
              <div className="grid grid-cols-3 gap-4 text-sm mb-3">
                <div><p className="text-white/50">Resources</p><p className="text-white font-bold">{r.resources}</p></div>
                <div><p className="text-white/50">Identities</p><p className="text-white font-bold">{r.identities}</p></div>
                <div><p className="text-white/50">Blast Radius</p><p className="text-white font-bold">{r.blastRadius}</p></div>
              </div>
              <div className="flex flex-wrap gap-2">
                {r.actions.map((a) => (<span key={a} className="text-xs bg-white/5 border border-white/10 rounded px-2 py-1 text-white/70">{a}</span>))}
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "response" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Response Actions</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { id: "RESP-001", finding: "ESC-001", action: "Lock Account", target: "dev-user-42", autoExecuted: true, success: true },
              { id: "RESP-002", finding: "ESC-005", action: "Restore Boundary", target: "PermissionBoundary-prod", autoExecuted: true, success: true },
              { id: "RESP-003", finding: "ESC-002", action: "Revert IAM Policy", target: "AdminAccess policy", autoExecuted: false, success: false },
              { id: "RESP-004", finding: "ESC-001", action: "Escalate Incident", target: "IR Team", autoExecuted: true, success: true },
            ].map((a) => (
              <div key={a.id} className="card-interactive p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs text-cyan-400">{a.id}</span>
                  <StatusBadge status={a.success ? "healthy" : "pending"} />
                </div>
                <h4 className="text-white/90 font-medium text-sm">{a.action}</h4>
                <p className="text-xs text-white/50 mt-1">Finding: {a.finding} | Target: {a.target}</p>
                <p className="text-xs text-white/40 mt-1">{a.autoExecuted ? "Auto-executed" : "Manual required"}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
