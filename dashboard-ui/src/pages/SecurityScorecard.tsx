import { useState } from "react";
import { BarChart3, TrendingUp, Target, Award, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "domains" | "trends" | "insights";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "domains", label: "Domains" }, { id: "trends", label: "Trends" }, { id: "insights", label: "Insights" }];
export default function SecurityScorecard() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Security Scorecard" subtitle="Real-time posture score — the board-level answer to 'how secure are we?'" icon={<BarChart3 className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Overall Score" value="B+" icon={<Award className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Score" value="82/100" icon={<Target className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="30d Trend" value="+7 pts" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Improvement Areas" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6 text-center"><div className="inline-block"><p className="text-6xl font-bold text-cyan-400">B+</p><p className="text-2xl text-white/80 mt-2">82 / 100</p><p className="text-sm text-emerald-400 mt-1">+7 points vs 30 days ago</p></div></div>)}
    {tab === "domains" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Domain</th><th className="px-4 py-3">Score</th><th className="px-4 py-3">Grade</th><th className="px-4 py-3">Trend</th></tr></thead>
      <tbody>{[
        { domain: "Endpoint Security", score: 91, grade: "A", trend: "stable" },
        { domain: "Identity & Access", score: 78, grade: "B", trend: "improving" },
        { domain: "Cloud Security", score: 84, grade: "B+", trend: "improving" },
        { domain: "Network Security", score: 88, grade: "A-", trend: "stable" },
        { domain: "Data Protection", score: 72, grade: "B-", trend: "improving" },
        { domain: "Application Security", score: 69, grade: "C+", trend: "at_risk" },
        { domain: "Compliance", score: 94, grade: "A", trend: "stable" },
        { domain: "Operations", score: 81, grade: "B+", trend: "improving" },
      ].map((d, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{d.domain}</td><td className="px-4 py-3 font-mono text-white/80">{d.score}</td><td className="px-4 py-3"><span className={clsx("font-bold", d.score >= 90 ? "text-emerald-400" : d.score >= 80 ? "text-cyan-400" : d.score >= 70 ? "text-yellow-400" : "text-red-400")}>{d.grade}</span></td><td className="px-4 py-3"><StatusBadge status={d.trend} /></td></tr>))}</tbody></table></div>)}
    {tab === "trends" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Score History (90 days)</h3>
      {[{ period: "90 days ago", score: 71, grade: "B-" }, { period: "60 days ago", score: 75, grade: "B" }, { period: "30 days ago", score: 75, grade: "B" }, { period: "Today", score: 82, grade: "B+" }].map((t, i) => (
        <div key={i} className="card-interactive p-3 flex items-center justify-between"><span className="text-white/60 text-sm">{t.period}</span><div className="flex items-center gap-3"><span className="font-mono text-white/80">{t.score}</span><span className={clsx("font-bold", t.score >= 80 ? "text-cyan-400" : "text-yellow-400")}>{t.grade}</span></div></div>))}</div>)}
    {tab === "insights" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">AI-Generated Insights</h3>
      {[{ insight: "Application security is your weakest domain (69/100) — OWASP testing found 34 unresolved vulnerabilities", action: "Run web_app_scanner weekly and auto-remediate trivial findings", priority: "high" },
        { insight: "Identity & access improved 12 points after deploying access_remediation agent", action: "Continue quarterly access reviews", priority: "positive" },
        { insight: "Patch compliance dropped 3% due to Java 17 rollback — 12 systems still unpatched", action: "Re-deploy with patch_orchestrator canary", priority: "medium" },
      ].map((i, idx) => (<div key={idx} className="card-interactive p-4"><p className="text-white/90 font-medium">{i.insight}</p><p className="text-xs text-cyan-400 mt-1">Action: {i.action}</p><StatusBadge status={i.priority} /></div>))}</div>)}
  </div>);
}
