import { useState } from "react";
import { Workflow, Play, Shield, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "playbooks" | "executions" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "playbooks", label: "Playbooks" },
  { id: "executions", label: "Executions" },
  { id: "metrics", label: "Metrics" },
];

const PLAYBOOKS = [
  {
    name: "Ransomware Response",
    category: "RANSOMWARE",
    steps: 12,
    status: "active",
    lastRun: "2h ago",
    successRate: "94%",
  },
  {
    name: "Phishing Containment",
    category: "PHISHING",
    steps: 8,
    status: "active",
    lastRun: "45m ago",
    successRate: "98%",
  },
  {
    name: "Data Breach Investigation",
    category: "DATA_BREACH",
    steps: 15,
    status: "active",
    lastRun: "1d ago",
    successRate: "91%",
  },
  {
    name: "DDoS Mitigation",
    category: "DDOS",
    steps: 6,
    status: "active",
    lastRun: "3d ago",
    successRate: "97%",
  },
  {
    name: "Insider Threat Response",
    category: "INSIDER_THREAT",
    steps: 10,
    status: "draft",
    lastRun: "Never",
    successRate: "N/A",
  },
];

const EXECUTIONS = [
  {
    id: "EX-001",
    playbook: "Phishing Containment",
    incident: "INC-4521",
    status: "completed",
    duration: "4m 32s",
    steps: "8/8",
  },
  {
    id: "EX-002",
    playbook: "Ransomware Response",
    incident: "INC-4519",
    status: "executing",
    duration: "12m (running)",
    steps: "7/12",
  },
  {
    id: "EX-003",
    playbook: "Data Breach Investigation",
    incident: "INC-4515",
    status: "completed",
    duration: "1h 23m",
    steps: "15/15",
  },
  {
    id: "EX-004",
    playbook: "DDoS Mitigation",
    incident: "INC-4512",
    status: "failed",
    duration: "2m 15s",
    steps: "4/6 (blocked at containment)",
  },
];

export default function IncidentPlaybookEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader
        title="Incident Playbook Engine"
        subtitle="Dynamic playbook generation, selection, and execution"
        icon={<Workflow className="h-6 w-6" />}
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Active Playbooks"
          value="24"
          icon={<Play className="h-5 w-5" />}
        />
        <MetricCard
          title="Executions (7d)"
          value="67"
          icon={<Workflow className="h-5 w-5 text-cyan-400" />}
        />
        <MetricCard
          title="Success Rate"
          value="94.3%"
          icon={<CheckCircle className="h-5 w-5 text-emerald-400" />}
        />
        <MetricCard
          title="Avg Duration"
          value="8.2 min"
          icon={<Clock className="h-5 w-5 text-yellow-400" />}
        />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx("tab-item", tab === t.id && "tab-item-active")}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6">
          <h3 className="section-heading">Execution Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { l: "Completed", v: "58", c: "text-emerald-400" },
              { l: "Running", v: "3", c: "text-cyan-400" },
              { l: "Failed", v: "4", c: "text-red-400" },
              { l: "Paused", v: "2", c: "text-yellow-400" },
            ].map((s) => (
              <div key={s.l} className="card-interactive p-4 text-center">
                <p className="text-sm text-white/60">{s.l}</p>
                <p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "playbooks" && (
        <div className="space-y-3">
          {PLAYBOOKS.map((p) => (
            <div key={p.name} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <span className="text-white/90 font-medium">{p.name}</span>
                <StatusBadge status={p.status} />
              </div>
              <div className="flex gap-4 text-sm text-white/50">
                <span>{p.category}</span>
                <span>{p.steps} steps</span>
                <span>Last: {p.lastRun}</span>
                <span className="text-emerald-400">{p.successRate}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "executions" && (
        <div className="space-y-3">
          {EXECUTIONS.map((e) => (
            <div key={e.id} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className="font-mono text-xs text-cyan-400">{e.id}</span>
                  <span className="ml-2 text-white/90 font-medium">{e.playbook}</span>
                </div>
                <StatusBadge status={e.status} />
              </div>
              <div className="flex gap-4 text-sm text-white/50">
                <span>{e.incident}</span>
                <span>{e.duration}</span>
                <span>Steps: {e.steps}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "metrics" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Playbook Performance</h3>
          {[
            { m: "Success Rate", v: "94.3%", t: "+2.1%" },
            { m: "Avg Execution Time", v: "8.2 min", t: "-1.4 min" },
            { m: "Auto-Selected", v: "82%", t: "+7%" },
            { m: "Steps Automated", v: "91%", t: "+3%" },
          ].map((x, i) => (
            <div
              key={i}
              className="card-interactive p-4 flex items-center justify-between"
            >
              <div>
                <p className="text-white/90 font-medium">{x.m}</p>
                <p className="text-xs text-white/50">{x.t}</p>
              </div>
              <span className="text-cyan-400 font-mono">{x.v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
