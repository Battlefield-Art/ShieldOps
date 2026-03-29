import { useState } from "react";
import { ShieldAlert, Zap, Target, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "rules" | "attacks" | "coverage";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "rules", label: "Rules" }, { id: "attacks", label: "Attacks" }, { id: "coverage", label: "Coverage" }];
export default function WAFManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="WAF Manager" subtitle="Web Application Firewall — rule tuning, OWASP coverage, false positive reduction" icon={<ShieldAlert className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Rules" value="342" icon={<ShieldAlert className="h-5 w-5" />} />
      <MetricCard title="Attacks Blocked" value="12.4K" icon={<Zap className="h-5 w-5 text-red-400" />} />
      <MetricCard title="False Positives" value="0.3%" icon={<Target className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="OWASP Coverage" value="96%" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Attack Categories (24h)</h3><div className="grid grid-cols-2 md:grid-cols-4 gap-3">{[{ cat: "SQLi", count: 3420, color: "text-red-400" }, { cat: "XSS", count: 2890, color: "text-yellow-400" }, { cat: "Path Traversal", count: 1240, color: "text-yellow-400" }, { cat: "RCE", count: 450, color: "text-red-400" }].map((c) => (<div key={c.cat} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{c.cat}</p><p className={clsx("text-xl font-bold mt-1", c.color)}>{c.count}</p></div>))}</div></div>)}
    {tab === "rules" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Rule</th><th className="px-4 py-3">Category</th><th className="px-4 py-3">Action</th><th className="px-4 py-3">FP Rate</th></tr></thead><tbody>{[{ name: "SQL Injection Detection", cat: "sqli", action: "block", fp: "0.1%" }, { name: "XSS Filter", cat: "xss", action: "block", fp: "0.4%" }, { name: "Rate Limiter", cat: "dos", action: "throttle", fp: "0.2%" }].map((r, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{r.name}</td><td className="px-4 py-3"><StatusBadge status={r.cat} /></td><td className="px-4 py-3 text-white/70">{r.action}</td><td className="px-4 py-3 text-emerald-400">{r.fp}</td></tr>))}</tbody></table></div>)}
    {tab === "attacks" && (<div className="space-y-3">{[{ id: "ATK-4521", type: "SQL Injection", src: "198.51.100.45", target: "/api/v1/users", status: "blocked" }, { id: "ATK-4520", type: "XSS Reflected", src: "203.0.113.12", target: "/search?q=", status: "blocked" }].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{a.id}</span><StatusBadge status={a.status} /></div><p className="text-white/90 font-medium">{a.type}</p><p className="text-xs text-white/50">{a.src} → {a.target}</p></div>))}</div>)}
    {tab === "coverage" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">OWASP Top 10 Coverage</h3>{[{ vuln: "A01: Broken Access Control", covered: true }, { vuln: "A02: Cryptographic Failures", covered: true }, { vuln: "A03: Injection", covered: true }, { vuln: "A04: Insecure Design", covered: false }].map((c, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between"><p className="text-white/90">{c.vuln}</p><StatusBadge status={c.covered ? "passing" : "failing"} /></div>))}</div>)}
  </div>);
}
