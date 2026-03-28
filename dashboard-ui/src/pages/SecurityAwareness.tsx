import { useState } from "react";
import { ShieldAlert, Mail, GraduationCap, Users, BarChart3, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "simulations" | "training" | "risk";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "simulations", label: "Phishing Simulations" },
  { id: "training", label: "Training Compliance" }, { id: "risk", label: "Risk Scores" },
];

export default function SecurityAwareness() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Awareness" subtitle="Phishing simulation results, training compliance, and per-user risk scoring" icon={<ShieldAlert className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Phishing Fail Rate" value="18%" icon={<Mail className="h-5 w-5" />} />
        <MetricCard title="Training Completion" value="87%" icon={<GraduationCap className="h-5 w-5" />} />
        <MetricCard title="High-Risk Users" value="12" icon={<AlertTriangle className="h-5 w-5" />} />
        <MetricCard title="Overall Score" value="72/100" icon={<BarChart3 className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Awareness Program Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { label: "Simulations Run (30d)", value: "6", sub: "3 phishing, 2 smishing, 1 vishing" },
              { label: "Avg Report Rate", value: "62%", sub: "Target: >70%" },
              { label: "Credential Submissions", value: "3", sub: "Down from 8 last month" },
            ].map((s) => (
              <div key={s.label} className="card-interactive p-4">
                <p className="text-sm text-white/60">{s.label}</p>
                <p className="text-3xl font-bold text-white mt-1">{s.value}</p>
                <p className="text-xs text-white/40 mt-1">{s.sub}</p>
              </div>
            ))}
          </div>
          <h3 className="section-heading mt-6">Department Risk Overview</h3>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {[
              { dept: "Engineering", risk: "Low", color: "text-emerald-400" },
              { dept: "Finance", risk: "High", color: "text-orange-400" },
              { dept: "Marketing", risk: "Medium", color: "text-yellow-400" },
              { dept: "HR", risk: "Medium", color: "text-yellow-400" },
              { dept: "Executive", risk: "Critical", color: "text-red-400" },
            ].map((d) => (
              <div key={d.dept} className="card-interactive p-3 text-center">
                <p className="text-sm text-white/60">{d.dept}</p>
                <p className={clsx("text-lg font-bold mt-1", d.color)}>{d.risk}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "simulations" && (
        <div className="space-y-3">
          {[
            { id: "SIM-301", type: "Phishing Email", subject: "Urgent: Password Reset Required", sent: 250, clicked: 42, reported: 155, cred: 3, date: "2026-03-25", status: "completed" },
            { id: "SIM-302", type: "Smishing", subject: "SMS: Verify your account", sent: 250, clicked: 58, reported: 108, cred: 0, date: "2026-03-20", status: "completed" },
            { id: "SIM-303", type: "Phishing Email", subject: "Shared Document: Q4 Strategy", sent: 250, clicked: 71, reported: 92, cred: 5, date: "2026-03-15", status: "completed" },
            { id: "SIM-304", type: "Vishing", subject: "IT Support callback request", sent: 50, clicked: 12, reported: 22, cred: 2, date: "2026-03-10", status: "completed" },
          ].map((sim) => (
            <div key={sim.id} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-xs text-cyan-400">{sim.id}</span>
                    <StatusBadge status={sim.status} />
                    <span className="text-xs text-white/40">{sim.type}</span>
                  </div>
                  <p className="text-white/90 font-medium">{sim.subject}</p>
                </div>
                <span className="text-xs text-white/40">{sim.date}</span>
              </div>
              <div className="flex items-center gap-4 text-xs text-white/50">
                <span>Sent: {sim.sent}</span>
                <span className="text-orange-400">Clicked: {sim.clicked} ({(sim.clicked / sim.sent * 100).toFixed(1)}%)</span>
                <span className="text-emerald-400">Reported: {sim.reported}</span>
                <span className="text-red-400">Cred submitted: {sim.cred}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "training" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Training Compliance by Department</h3>
          {[
            { dept: "Engineering", assigned: 45, completed: 42, overdue: 1, avgScore: 91, status: "on_track" },
            { dept: "Finance", assigned: 30, completed: 22, overdue: 5, avgScore: 78, status: "at_risk" },
            { dept: "Marketing", assigned: 25, completed: 21, overdue: 2, avgScore: 82, status: "on_track" },
            { dept: "HR", assigned: 15, completed: 12, overdue: 2, avgScore: 85, status: "on_track" },
            { dept: "Executive", assigned: 10, completed: 6, overdue: 3, avgScore: 72, status: "at_risk" },
          ].map((d) => (
            <div key={d.dept} className="card-interactive p-4 flex items-center justify-between">
              <div>
                <p className="text-white/90 font-medium">{d.dept}</p>
                <div className="flex items-center gap-3 text-xs text-white/50 mt-1">
                  <span className="flex items-center gap-1"><CheckCircle className="h-3 w-3 text-emerald-400" />{d.completed}/{d.assigned} completed</span>
                  {d.overdue > 0 && <span className="flex items-center gap-1"><Clock className="h-3 w-3 text-orange-400" />{d.overdue} overdue</span>}
                  <span>Avg score: {d.avgScore}%</span>
                </div>
              </div>
              <StatusBadge status={d.status === "at_risk" ? "warning" : "active"} />
            </div>
          ))}
        </div>
      )}
      {tab === "risk" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">User Risk Scoring</h3>
          <div className="grid grid-cols-2 gap-4 mb-4">
            {[
              { metric: "Avg Risk Score", value: "38.2", target: "<30" },
              { metric: "High-Risk Users", value: "12", target: "<5" },
              { metric: "Repeat Offenders", value: "4", target: "0" },
              { metric: "Improved (30d)", value: "23", target: ">20" },
            ].map((m) => (
              <div key={m.metric} className="card-interactive p-4">
                <p className="text-sm text-white/60">{m.metric}</p>
                <p className="text-2xl font-bold text-white mt-1">{m.value}</p>
                <p className="text-xs text-white/40">Target: {m.target}</p>
              </div>
            ))}
          </div>
          <h3 className="section-heading">Top Risk Users</h3>
          {[
            { email: "j.smith@acme.com", dept: "Finance", score: 82, tier: "critical", factors: "3x phishing fail, no training" },
            { email: "m.jones@acme.com", dept: "Executive", score: 75, tier: "high", factors: "Credential submission, overdue training" },
            { email: "a.lee@acme.com", dept: "HR", score: 68, tier: "high", factors: "2x link click, low training score" },
            { email: "r.patel@acme.com", dept: "Finance", score: 62, tier: "high", factors: "Repeated smishing fail" },
          ].map((u) => (
            <div key={u.email} className="card-interactive p-4 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-white/90 font-medium">{u.email}</span>
                  <StatusBadge status={u.tier === "critical" ? "critical" : "high"} />
                </div>
                <p className="text-xs text-white/50">{u.dept} | Score: {u.score} | {u.factors}</p>
              </div>
              <Users className="h-4 w-4 text-white/30" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
