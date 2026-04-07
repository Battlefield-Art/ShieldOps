import { useState } from "react";
import { Play, CheckCircle, XCircle, Shield, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "scenarios" | "results" | "regression";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "scenarios", label: "Scenarios" }, { id: "results", label: "Results" }, { id: "regression", label: "Regression" }];
export default function ThreatScenarioRunner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Threat Scenario Runner" subtitle="Regression testing for security controls — run scenarios, get pass/fail" icon={<Play className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Scenarios" value="24" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Passing" value="19" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Failing" value="3" icon={<XCircle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Pass Rate" value="79.2%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Scenario Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ cat: "Ransomware", pass: 4, fail: 0, color: "text-emerald-400" }, { cat: "Credential Theft", pass: 3, fail: 1, color: "text-yellow-400" }, { cat: "Cloud Breach", pass: 3, fail: 1, color: "text-yellow-400" }, { cat: "Data Exfil", pass: 2, fail: 1, color: "text-yellow-400" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cat}</p><p className={clsx("text-xl font-bold mt-1", c.color)}>{c.pass} pass / {c.fail} fail</p></div>))}</div></div>)}
    {tab === "scenarios" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Scenario</th><th className="px-4 py-3">Steps</th><th className="px-4 py-3">Controls</th><th className="px-4 py-3">Verdict</th></tr></thead>
      <tbody>{[
        { name: "Ransomware kill chain", steps: 8, controls: 8, verdict: "pass" },
        { name: "Credential phishing + MFA bypass", steps: 5, controls: 4, verdict: "fail" },
        { name: "S3 data exfil via API", steps: 4, controls: 3, verdict: "fail" },
        { name: "Insider data hoarding", steps: 6, controls: 6, verdict: "pass" },
        { name: "Container escape + pivot", steps: 5, controls: 5, verdict: "pass" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.name}</td><td className="px-4 py-3 text-white/80">{s.steps}</td><td className="px-4 py-3 text-white/70">{s.controls} tested</td><td className="px-4 py-3"><StatusBadge status={s.verdict} /></td></tr>))}</tbody></table></div>)}
    {tab === "results" && (<div className="space-y-3">
      {[{ scenario: "Credential phishing + MFA bypass", failure: "MFA fatigue attack succeeded on 3rd attempt", fix: "Enable number matching for MFA push", status: "fail" },
        { scenario: "S3 data exfil via API", failure: "No DLP on API-level S3 GetObject calls", fix: "Deploy data_loss_prevention agent on API layer", status: "fail" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{r.scenario}</p><StatusBadge status={r.status} /></div>
        <p className="text-xs text-red-400">{r.failure}</p><p className="text-xs text-cyan-400 mt-1">Fix: {r.fix}</p></div>))}</div>)}
    {tab === "regression" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Regression Detection</h3>
      {[{ scenario: "DNS exfil detection", was: "pass (2 weeks ago)", now: "fail", cause: "DNS monitoring rule disabled during maintenance" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{r.scenario}</p><p className="text-xs text-white/50">Was: {r.was} | Now: {r.now}</p><p className="text-xs text-red-400 mt-1">Cause: {r.cause}</p></div>))}</div>)}
  </div>);
}
