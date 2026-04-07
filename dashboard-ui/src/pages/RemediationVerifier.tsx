import { useState } from "react";
import { CheckCircle, AlertTriangle, RefreshCw, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "tests" | "results" | "regressions";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "tests", label: "Tests" }, { id: "results", label: "Results" }, { id: "regressions", label: "Regressions" }];
export default function RemediationVerifier() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Remediation Verifier" subtitle="Re-test after every fix to prove it actually worked" icon={<CheckCircle className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Remediations Tested" value="52" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Verified Fixed" value="48" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Still Vulnerable" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Regressions" value="1" icon={<RefreshCw className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Verification Results</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ result: "Fixed", count: 48, pct: "92.3%", color: "text-emerald-400" }, { result: "Partial", count: 1, pct: "1.9%", color: "text-yellow-400" }, { result: "Not Fixed", count: 2, pct: "3.8%", color: "text-red-400" }, { result: "Regression", count: 1, pct: "1.9%", color: "text-red-400" }].map((r) => (
        <div key={r.result} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{r.result}</p><p className={clsx("text-3xl font-bold mt-1", r.color)}>{r.pct}</p></div>))}</div></div>)}
    {tab === "tests" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Verification Tests</h3>
      {[{ vuln: "S3 public access", test: "Attempt anonymous GET", expected: "403 Forbidden", actual: "403 Forbidden", result: "fixed" },
        { vuln: "SSH weak ciphers", test: "Negotiate with weak cipher", expected: "Connection refused", actual: "Connection refused", result: "fixed" },
        { vuln: "SQLi in /api/users", test: "Inject ' OR 1=1 --", expected: "400 Bad Request", actual: "200 OK with data", result: "not_fixed" },
      ].map((t, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{t.vuln}</p><StatusBadge status={t.result} /></div>
        <p className="text-xs text-white/50">Test: {t.test}</p><p className="text-xs text-white/50">Expected: {t.expected} | Actual: {t.actual}</p></div>))}</div>)}
    {tab === "results" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Finding</th><th className="px-4 py-3">Fix Applied</th><th className="px-4 py-3">Re-Test</th><th className="px-4 py-3">Result</th></tr></thead>
      <tbody>{[
        { finding: "Public S3 bucket", fix: "ACL restricted", retest: "Anonymous GET → 403", result: "fixed" },
        { finding: "Weak SSH ciphers", fix: "sshd_config updated", retest: "Cipher negotiation fails", result: "fixed" },
        { finding: "SQLi in /api/users", fix: "Input validation added", retest: "Injection still works", result: "not_fixed" },
      ].map((r, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{r.finding}</td><td className="px-4 py-3 text-white/70">{r.fix}</td><td className="px-4 py-3 text-white/60">{r.retest}</td><td className="px-4 py-3"><StatusBadge status={r.result} /></td></tr>))}</tbody></table></div>)}
    {tab === "regressions" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detected Regressions</h3>
      {[{ vuln: "Open redirect on /login", detail: "Was fixed 2 weeks ago, regression after deploy v2.3.1", severity: "high", status: "reopened" }
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.vuln}</p><p className="text-xs text-white/50">{r.detail}</p></div><StatusBadge status={r.severity} /></div>))}</div>)}
  </div>);
}
