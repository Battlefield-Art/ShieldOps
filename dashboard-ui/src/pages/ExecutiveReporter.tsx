import { useState } from "react";
import { FileText, TrendingUp, Shield, Calendar, Download } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "latest" | "history" | "schedule";
const TABS: { id: TabId; label: string }[] = [{ id: "latest", label: "Latest Report" }, { id: "history", label: "History" }, { id: "schedule", label: "Schedule" }];
export default function ExecutiveReporter() {
  const [tab, setTab] = useState<TabId>("latest");
  return (<div className="space-y-6">
    <PageHeader title="Executive Reporter" subtitle="Auto-generated CISO reports with posture trends, findings, and recommendations" icon={<FileText className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Reports Generated" value="24" icon={<FileText className="h-5 w-5" />} />
      <MetricCard title="Latest Score" value="B+ (82)" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Trend" value="+7 pts" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Next Report" value="3 days" icon={<Calendar className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "latest" && (<div className="card-surface p-6 space-y-4"><div className="flex items-center justify-between"><h3 className="section-heading">Weekly Security Posture Report</h3><button className="btn-primary px-3 py-1 text-xs flex items-center gap-1"><Download className="h-3 w-3" /> Export PDF</button></div>
      <div className="card-interactive p-4"><h4 className="text-white/90 font-medium mb-2">Executive Summary</h4><p className="text-sm text-white/70">Security posture improved to B+ (82/100), up 7 points from last month. Key drivers: access remediation agent removed 1,200 excess permissions, and patch orchestrator brought critical patch compliance to 95.9%. Application security remains the weakest domain at C+ (69) — recommend prioritizing web app scanner findings.</p></div>
      <div className="card-interactive p-4"><h4 className="text-white/90 font-medium mb-2">Key Findings This Week</h4><ul className="text-sm text-white/60 space-y-1"><li>- 47 new vulnerabilities found by pentest agents (12 critical)</li><li>- 38 misconfigurations auto-fixed by config_remediation</li><li>- 3 credential leaks detected and rotated</li><li>- 1 phishing simulation: 12.3% click rate (down from 23%)</li><li>- MITRE coverage: 78.4% (up from 74%)</li></ul></div>
      <div className="card-interactive p-4"><h4 className="text-white/90 font-medium mb-2">Recommendations</h4><ol className="text-sm text-white/60 space-y-1"><li>1. Deploy web app scanner on CI/CD pipeline for shift-left</li><li>2. Close 16 detection blind spots identified by gap finder</li><li>3. Enable auto-remediation for medium-severity configs</li><li>4. Schedule quarterly attack readiness assessment</li></ol></div></div>)}
    {tab === "history" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Report</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Score</th><th className="px-4 py-3">Date</th></tr></thead>
      <tbody>{[
        { name: "Weekly Posture — Week 12", type: "weekly_posture", score: "B+ (82)", date: "Mar 24" },
        { name: "Weekly Posture — Week 11", type: "weekly_posture", score: "B (78)", date: "Mar 17" },
        { name: "Monthly Executive — Feb", type: "monthly_executive", score: "B (75)", date: "Mar 1" },
        { name: "Quarterly Board — Q4", type: "quarterly_board", score: "B- (71)", date: "Jan 15" },
      ].map((r, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{r.name}</td><td className="px-4 py-3"><StatusBadge status={r.type} /></td><td className="px-4 py-3 text-cyan-400">{r.score}</td><td className="px-4 py-3 text-white/50">{r.date}</td></tr>))}</tbody></table></div>)}
    {tab === "schedule" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Report Schedule</h3>
      {[{ type: "Weekly Posture", frequency: "Every Monday 8am", recipients: "CISO, Security Team", status: "active" },
        { type: "Monthly Executive", frequency: "1st of month", recipients: "CISO, CTO, VP Engineering", status: "active" },
        { type: "Quarterly Board", frequency: "Jan/Apr/Jul/Oct 15th", recipients: "Board of Directors", status: "active" },
        { type: "Incident Summary", frequency: "On-demand", recipients: "CISO, Incident Team", status: "active" },
      ].map((s, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{s.type}</p><p className="text-xs text-white/50">{s.frequency} | To: {s.recipients}</p></div><StatusBadge status={s.status} /></div>))}</div>)}
  </div>);
}
