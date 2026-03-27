import { useState } from "react";
import { Globe, Shield, AlertTriangle, Code, Bug, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "owasp" | "endpoints";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "owasp", label: "OWASP Top 10" }, { id: "endpoints", label: "Endpoints" }];
export default function WebAppScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Web App Scanner" subtitle="OWASP Top 10 automated testing — XSS, SQLi, SSRF, auth bypass, IDOR" icon={<Globe className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Apps Scanned" value="12" icon={<Globe className="h-5 w-5" />} />
      <MetricCard title="Endpoints Tested" value="847" icon={<Code className="h-5 w-5" />} />
      <MetricCard title="Vulnerabilities" value="34" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="OWASP Coverage" value="9/10" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Vulnerability Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ type: "SQL Injection", count: 8, color: "text-red-400" }, { type: "XSS", count: 12, color: "text-red-400" }, { type: "Auth Bypass", count: 5, color: "text-yellow-400" }, { type: "Misconfig", count: 9, color: "text-yellow-400" }].map((v) => (
        <div key={v.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{v.type}</p><p className={clsx("text-3xl font-bold mt-1", v.color)}>{v.count}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="space-y-3">
      {[{ id: "WAS-034", vuln: "SQL Injection in /api/users?id=", app: "customer-portal", type: "sqli", severity: "critical", payload: "' OR 1=1 --" },
        { id: "WAS-033", vuln: "Reflected XSS in search parameter", app: "support-app", type: "xss", severity: "high", payload: "<script>alert(1)</script>" },
        { id: "WAS-032", vuln: "SSRF via image upload URL", app: "cms", type: "ssrf", severity: "high", payload: "http://169.254.169.254/meta-data" },
        { id: "WAS-031", vuln: "IDOR — access other users' orders", app: "customer-portal", type: "idor", severity: "high", payload: "/api/orders/OTHER_USER_ID" },
      ].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="text-xs text-white/40 ml-2">{f.app}</span></div><StatusBadge status={f.severity} /></div>
        <p className="text-white/90 font-medium">{f.vuln}</p><p className="text-xs text-white/50 font-mono">Type: {f.type}</p></div>))}</div>)}
    {tab === "owasp" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">OWASP Category</th><th className="px-4 py-3">Tested</th><th className="px-4 py-3">Findings</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { cat: "A01 — Broken Access Control", tested: true, findings: 7, status: "vulnerable" },
        { cat: "A02 — Cryptographic Failures", tested: true, findings: 2, status: "at_risk" },
        { cat: "A03 — Injection", tested: true, findings: 12, status: "vulnerable" },
        { cat: "A04 — Insecure Design", tested: true, findings: 3, status: "at_risk" },
        { cat: "A05 — Security Misconfiguration", tested: true, findings: 5, status: "vulnerable" },
        { cat: "A06 — Vuln & Outdated Components", tested: true, findings: 3, status: "at_risk" },
        { cat: "A07 — Auth Failures", tested: true, findings: 2, status: "at_risk" },
        { cat: "A08 — Software Integrity", tested: true, findings: 0, status: "passed" },
        { cat: "A09 — Logging Failures", tested: true, findings: 0, status: "passed" },
        { cat: "A10 — SSRF", tested: true, findings: 2, status: "vulnerable" },
      ].map((o, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{o.cat}</td><td className="px-4 py-3">{o.tested ? "Yes" : "No"}</td><td className="px-4 py-3 text-white/80">{o.findings}</td><td className="px-4 py-3"><StatusBadge status={o.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "endpoints" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Tested Endpoints</h3>
      {[{ endpoint: "POST /api/users", app: "customer-portal", tests: 12, vulns: 2, status: "vulnerable" },
        { endpoint: "GET /api/search", app: "support-app", tests: 8, vulns: 1, status: "vulnerable" },
        { endpoint: "POST /api/upload", app: "cms", tests: 6, vulns: 1, status: "vulnerable" },
        { endpoint: "GET /api/orders/{id}", app: "customer-portal", tests: 10, vulns: 1, status: "vulnerable" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium font-mono text-sm">{e.endpoint}</p><p className="text-xs text-white/50">{e.app} | {e.tests} tests | {e.vulns} vulns</p></div><StatusBadge status={e.status} /></div>))}</div>)}
  </div>);
}
