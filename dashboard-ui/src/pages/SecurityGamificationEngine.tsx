import { useState } from "react";
import { Trophy, Users, Target, Activity, Award, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "challenges" | "leaderboard" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "challenges", label: "Challenges" },
  { id: "leaderboard", label: "Leaderboard" },
  { id: "metrics", label: "Metrics" },
];

const CHALLENGES = [
  { id: "CH-001", name: "Phishing Detection Blitz", type: "phishing_quiz", difficulty: "medium", participants: 234, completion: "78%", status: "active" },
  { id: "CH-002", name: "CTF: Privilege Escalation", type: "ctf_challenge", difficulty: "hard", participants: 89, completion: "42%", status: "active" },
  { id: "CH-003", name: "Secure Code Review Sprint", type: "secure_coding", difficulty: "medium", participants: 156, completion: "65%", status: "active" },
  { id: "CH-004", name: "Incident Response Drill", type: "incident_drill", difficulty: "hard", participants: 67, completion: "91%", status: "completed" },
];

const LEADERBOARD = [
  { rank: 1, name: "Alice Chen", team: "Platform Eng", points: 4820, badges: 12, streak: 45 },
  { rank: 2, name: "Bob Martinez", team: "Security Ops", points: 4650, badges: 11, streak: 38 },
  { rank: 3, name: "Carol Kim", team: "Cloud Infra", points: 4210, badges: 10, streak: 32 },
  { rank: 4, name: "Dave Patel", team: "Dev Team A", points: 3890, badges: 9, streak: 28 },
  { rank: 5, name: "Eve Johnson", team: "Security Ops", points: 3740, badges: 8, streak: 25 },
];

export default function SecurityGamificationEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Gamification Engine" subtitle="Security awareness gamification, challenges, and leaderboards" icon={<Trophy className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Participants" value="546" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Challenges Active" value="8" icon={<Target className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Badges Awarded" value="1,247" icon={<Award className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Avg Score" value="72.4" icon={<Activity className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Engagement Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Completion Rate", v: "78%", c: "text-emerald-400" }, { l: "Avg Accuracy", v: "84%", c: "text-cyan-400" }, { l: "Active Streaks", v: "312", c: "text-yellow-400" }, { l: "Teams Competing", v: "24", c: "text-purple-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "challenges" && (<div className="space-y-3">{CHALLENGES.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-white/90 font-medium">{c.name}</span></div><StatusBadge status={c.status} /></div><div className="flex gap-4 text-sm text-white/60"><span>Type: {c.type}</span><span>Difficulty: {c.difficulty}</span><span>Participants: {c.participants}</span><span>Completion: {c.completion}</span></div></div>))}</div>)}
      {tab === "leaderboard" && (<div className="space-y-3">{LEADERBOARD.map((e) => (<div key={e.rank} className="card-interactive p-4"><div className="flex items-center justify-between"><div className="flex items-center gap-4"><span className={clsx("text-lg font-bold", e.rank === 1 ? "text-yellow-400" : e.rank === 2 ? "text-gray-300" : e.rank === 3 ? "text-orange-400" : "text-white/60")}>#{e.rank}</span><div><p className="text-white/90 font-medium">{e.name}</p><p className="text-xs text-white/50">{e.team}</p></div></div><div className="flex items-center gap-6 text-sm"><span className="text-cyan-400 font-mono">{e.points} pts</span><span className="text-yellow-400">{e.badges} badges</span><span className="text-white/50">{e.streak}d streak</span></div></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Campaign Metrics</h3>{[{ m: "Phishing Detection Rate", v: "89%", t: "+12% since campaign start" }, { m: "Incident Report Rate", v: "+34%", t: "More employees reporting" }, { m: "Policy Compliance", v: "92%", t: "+8% improvement" }, { m: "Security Culture Score", v: "7.8/10", t: "+1.2 vs last quarter" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
