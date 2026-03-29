import { useState } from "react";
import { Code, Shield, AlertTriangle, Bug, FileSearch, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "dataflow" | "reports";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "dataflow", label: "Dataflow" }, { id: "reports", label: "Reports" }];
export default function SASTScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="SAST Scanner" subtitle="Static application security testing with LLM-enhanced pattern and dataflow analysis" icon={<Code className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Files Scanned" value="1,247" icon={<FileSearch className="h-5 w-5" />} />
      <MetricCard title="Findings" value="156" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Critical" value="12" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Fix Rate" value="91%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Vulnerability Categories</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ cat: "SQL Injection", count: 18, color: "text-red-400" }, { cat: "XSS", count: 24, color: "text-yellow-400" }, { cat: "Command Injection", count: 9, color: "text-red-400" }, { cat: "Hardcoded Secrets", count: 15, color: "text-yellow-400" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cat}</p><p className={clsx("text-3xl font-bold mt-1", c.color)}>{c.count}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Finding</th><th className="px-4 py-3">File</th><th className="px-4 py-3">CWE</th><th className="px-4 py-3">Severity</th></tr></thead>
      <tbody>{[
        { finding: "SQL injection via f-string", file: "api/users.py:42", cwe: "CWE-89", sev: "critical" },
        { finding: "eval() with user input", file: "utils/parser.py:18", cwe: "CWE-94", sev: "critical" },
        { finding: "Hardcoded API key", file: "config/settings.py:7", cwe: "CWE-798", sev: "high" },
        { finding: "TLS verification disabled", file: "connectors/api.py:55", cwe: "CWE-295", sev: "medium" },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{f.finding}</td><td className="px-4 py-3 font-mono text-xs text-white/60">{f.file}</td><td className="px-4 py-3 text-cyan-400">{f.cwe}</td><td className="px-4 py-3"><StatusBadge status={f.sev} /></td></tr>))}</tbody></table></div>)}
    {tab === "dataflow" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Taint Propagation Traces</h3>
      {[{ source: "request.params['id']", sink: "db.execute(query)", hops: 3, severity: "critical" },
        { source: "request.body['name']", sink: "template.render()", hops: 2, severity: "high" },
        { source: "os.environ['PATH']", sink: "subprocess.run()", hops: 4, severity: "high" },
      ].map((t, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><div className="flex items-center gap-2"><Zap className="h-4 w-4 text-cyan-400" /><span className="text-white/90 font-medium">{t.source} → {t.sink}</span></div><StatusBadge status={t.severity} /></div>
        <p className="text-xs text-white/50">{t.hops} hops in taint chain</p></div>))}</div>)}
    {tab === "reports" && (<div className="card-surface p-6"><h3 className="section-heading">Recent Scan Reports</h3>
      {[{ date: "2026-03-28 09:15", files: 412, findings: 34, critical: 3, duration: "12.4s" },
        { date: "2026-03-27 14:30", files: 389, findings: 28, critical: 2, duration: "10.8s" },
        { date: "2026-03-26 11:00", files: 446, findings: 41, critical: 5, duration: "14.1s" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.date}</p><p className="text-xs text-white/50">{r.files} files | {r.findings} findings | {r.critical} critical | {r.duration}</p></div><StatusBadge status={r.critical > 3 ? "critical" : "healthy"} /></div>))}</div>)}
  </div>);
}
