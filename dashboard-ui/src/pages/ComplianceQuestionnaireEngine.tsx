import { useState } from "react";
import { ClipboardList, FileCheck, AlertTriangle, Target, BookOpen, Search } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "questionnaires" | "answer_library" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "questionnaires", label: "Questionnaires" },
  { id: "answer_library", label: "Answer Library" },
  { id: "metrics", label: "Metrics" },
];

const QUESTIONNAIRES = [
  { id: "QST-001", name: "Acme Corp SOC 2 Assessment", framework: "SOC 2", status: "in_progress", questions: 142, answered: 128, gaps: 6 },
  { id: "QST-002", name: "HealthFirst HIPAA Review", framework: "HIPAA", status: "completed", questions: 89, answered: 89, gaps: 0 },
  { id: "QST-003", name: "GlobalBank PCI DSS Audit", framework: "PCI DSS", status: "in_progress", questions: 210, answered: 185, gaps: 12 },
  { id: "QST-004", name: "EU Partner GDPR Questionnaire", framework: "GDPR", status: "pending", questions: 67, answered: 0, gaps: 0 },
];

const ANSWERS = [
  { id: "ANS-001", question: "Describe your access control policy", framework: "SOC 2", reuse_count: 14, confidence: 0.95, status: "approved" },
  { id: "ANS-002", question: "How is PHI encrypted at rest?", framework: "HIPAA", reuse_count: 8, confidence: 0.92, status: "approved" },
  { id: "ANS-003", question: "Describe your incident response process", framework: "SOC 2", reuse_count: 22, confidence: 0.97, status: "approved" },
  { id: "ANS-004", question: "How do you handle data subject requests?", framework: "GDPR", reuse_count: 5, confidence: 0.88, status: "pending_review" },
];

export default function ComplianceQuestionnaireEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Compliance Questionnaire Engine" subtitle="Automated compliance questionnaire management and answer generation" icon={<ClipboardList className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Questionnaires" value="3" icon={<ClipboardList className="h-5 w-5" />} />
        <MetricCard title="Questions Answered" value="402" icon={<FileCheck className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Coverage Score" value="91%" icon={<Target className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Open Gaps" value="18" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Framework Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "SOC 2", v: "94%", c: "text-emerald-400" }, { l: "HIPAA", v: "100%", c: "text-cyan-400" }, { l: "PCI DSS", v: "88%", c: "text-yellow-400" }, { l: "GDPR", v: "76%", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "questionnaires" && (<div className="space-y-3">{QUESTIONNAIRES.map((q) => (<div key={q.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{q.id}</span><span className="ml-2 text-xs text-white/40">{q.framework}</span></div><StatusBadge status={q.status} /></div><p className="text-white/90 text-sm font-medium">{q.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{q.answered}/{q.questions} answered</span>{q.gaps > 0 && <span className="text-yellow-400">{q.gaps} gaps</span>}<span>{q.questions > 0 ? Math.round((q.answered / q.questions) * 100) : 0}% complete</span></div></div>))}</div>)}
      {tab === "answer_library" && (<div className="space-y-3">{ANSWERS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.framework}</span></div><StatusBadge status={a.status} /></div><p className="text-white/90 text-sm">{a.question}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Reused {a.reuse_count}x</span><span className="text-emerald-400">Confidence: {(a.confidence * 100).toFixed(0)}%</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Questionnaire Performance</h3>{[{ m: "Avg Response Time", v: "2.4 days", t: "-1.2 days" }, { m: "Auto-Answer Rate", v: "78%", t: "+12%" }, { m: "Gap Closure Rate", v: "92%", t: "+5%" }, { m: "Answer Reuse Rate", v: "64%", t: "+8%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
