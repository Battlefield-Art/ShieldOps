import { useState } from "react";
import { Cloud, Shield, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "misconfigs" | "benchmarks" | "remediation";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "misconfigs", label: "Misconfigurations" },
  { id: "benchmarks", label: "CIS Benchmarks" }, { id: "remediation", label: "Remediation" },
];

export default function CloudPosture() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Posture (CSPM)" subtitle="Multi-cloud security posture assessment against CIS benchmarks" icon={<Cloud className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Posture Score" value="78%" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Misconfigurations" value="34" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Resources Scanned" value="2,847" icon={<Cloud className="h-5 w-5" />} />
        <MetricCard title="Auto-Remediated" value="18" icon={<CheckCircle className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Provider Posture</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ provider: "AWS", score: 82, misconfigs: 14, resources: 1240 }, { provider: "GCP", score: 76, misconfigs: 12, resources: 890 }, { provider: "Kubernetes", score: 71, misconfigs: 8, resources: 717 }].map((p) => (
              <div key={p.provider} className="card-interactive p-4">
                <div className="flex items-center justify-between mb-2"><span className="text-white/90 font-medium">{p.provider}</span><span className={clsx("text-lg font-bold", p.score >= 80 ? "text-emerald-400" : p.score >= 70 ? "text-yellow-400" : "text-red-400")}>{p.score}%</span></div>
                <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${p.score}%` }} /></div>
                <p className="text-xs text-white/40 mt-2">{p.resources} resources | {p.misconfigs} misconfigs</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "misconfigs" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Resource</th><th className="px-4 py-3">Provider</th><th className="px-4 py-3">Issue</th><th className="px-4 py-3">CIS</th><th className="px-4 py-3">Severity</th><th className="px-4 py-3">Fix</th></tr></thead>
            <tbody>
              {[
                { resource: "s3-logs-prod", provider: "AWS", issue: "Public read access enabled", cis: "2.1.2", severity: "critical", fix: true },
                { resource: "gke-cluster-01", provider: "GCP", issue: "RBAC not enforced", cis: "5.1.1", severity: "high", fix: true },
                { resource: "rds-primary", provider: "AWS", issue: "Encryption at rest disabled", cis: "2.3.1", severity: "high", fix: true },
                { resource: "k8s-default-ns", provider: "K8s", issue: "Default namespace in use", cis: "5.7.1", severity: "medium", fix: false },
              ].map((m, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 font-mono text-xs text-cyan-400">{m.resource}</td>
                  <td className="px-4 py-3 text-white/70">{m.provider}</td>
                  <td className="px-4 py-3 text-white/80">{m.issue}</td>
                  <td className="px-4 py-3 text-white/60">{m.cis}</td>
                  <td className="px-4 py-3"><StatusBadge status={m.severity} /></td>
                  <td className="px-4 py-3">{m.fix ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-white/30" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "benchmarks" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">CIS Benchmark Compliance</h3>
          {[{ fw: "CIS AWS v3.0", pass: 142, fail: 14, total: 160 }, { fw: "CIS GCP v2.0", pass: 98, fail: 12, total: 115 }, { fw: "CIS K8s v1.8", pass: 78, fail: 8, total: 92 }].map((b) => (
            <div key={b.fw} className="card-interactive p-4">
              <div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{b.fw}</p><span className="text-sm text-white/60">{b.pass}/{b.total} passing</span></div>
              <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${(b.pass / b.total) * 100}%` }} /></div>
            </div>
          ))}
        </div>
      )}
      {tab === "remediation" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Auto-Remediation Log</h3>
          {[
            { action: "Enable S3 encryption", target: "s3-logs-prod", status: "completed", when: "12 min ago" },
            { action: "Block public access", target: "s3-uploads-staging", status: "completed", when: "28 min ago" },
            { action: "Enable audit logging", target: "gke-cluster-01", status: "pending", when: "Scheduled" },
          ].map((r, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.target} | {r.when}</p></div>
              <StatusBadge status={r.status} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
