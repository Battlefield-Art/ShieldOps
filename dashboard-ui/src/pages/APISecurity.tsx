import { useState } from "react";
import { Globe, AlertTriangle, Zap, Activity, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "vulnerabilities" | "abuse" | "policies";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "abuse", label: "Abuse Detection" },
  { id: "policies", label: "Enforced Policies" },
];

export default function APISecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="API Security" subtitle="OWASP API Top 10 detection and API abuse monitoring" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Endpoints Monitored" value="342" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Open Vulnerabilities" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Abuse Incidents (24h)" value="7" icon={<Zap className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Policies Active" value="28" icon={<Lock className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">OWASP API Top 10 Coverage</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { id: "API1", name: "BOLA", findings: 3, color: "text-red-400" },
              { id: "API2", name: "Broken Auth", findings: 2, color: "text-red-400" },
              { id: "API3", name: "Excessive Data", findings: 4, color: "text-yellow-400" },
              { id: "API4", name: "Resource Limits", findings: 1, color: "text-yellow-400" },
              { id: "API5", name: "Function Auth", findings: 0, color: "text-emerald-400" },
              { id: "API6", name: "Mass Assignment", findings: 1, color: "text-yellow-400" },
              { id: "API7", name: "Misconfig", findings: 1, color: "text-yellow-400" },
              { id: "API8", name: "Injection", findings: 0, color: "text-emerald-400" },
              { id: "API9", name: "Asset Mgmt", findings: 0, color: "text-emerald-400" },
              { id: "API10", name: "SSRF", findings: 0, color: "text-emerald-400" },
            ].map((o) => (
              <div key={o.id} className="card-interactive p-3 text-center">
                <p className="text-xs text-white/50">{o.id}</p>
                <p className={clsx("text-lg font-bold", o.color)}>{o.findings}</p>
                <p className="text-xs text-white/40">{o.name}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "vulnerabilities" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Endpoint</th><th className="px-4 py-3">OWASP</th><th className="px-4 py-3">Severity</th><th className="px-4 py-3">CWE</th><th className="px-4 py-3">Description</th></tr></thead>
            <tbody>
              {[
                { ep: "GET /api/v1/users/{id}", owasp: "API1:BOLA", severity: "critical", cwe: "CWE-639", desc: "No object-level auth check" },
                { ep: "POST /api/v1/auth/login", owasp: "API2:BrokenAuth", severity: "high", cwe: "CWE-307", desc: "No brute-force protection" },
                { ep: "GET /api/v1/orders", owasp: "API3:ExcessiveData", severity: "medium", cwe: "CWE-213", desc: "Returns PII in response" },
                { ep: "POST /api/v1/agents/run", owasp: "API4:ResourceLimits", severity: "high", cwe: "CWE-770", desc: "No rate limit on agent execution" },
              ].map((v, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 font-mono text-xs text-cyan-400">{v.ep}</td>
                  <td className="px-4 py-3 text-white/70">{v.owasp}</td>
                  <td className="px-4 py-3"><StatusBadge status={v.severity} /></td>
                  <td className="px-4 py-3 text-white/60">{v.cwe}</td>
                  <td className="px-4 py-3 text-white/70">{v.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "abuse" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Active Abuse Incidents</h3>
          {[
            { type: "Credential Stuffing", source: "203.0.113.42", endpoint: "/api/v1/auth/login", count: "12,400 req/hr", status: "blocked" },
            { type: "Data Scraping", source: "198.51.100.0/24", endpoint: "/api/v1/products", count: "8,900 req/hr", status: "rate_limited" },
            { type: "User Enumeration", source: "192.0.2.100", endpoint: "/api/v1/users/check", count: "3,200 req/hr", status: "monitoring" },
          ].map((a, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{a.type}</p><p className="text-xs text-white/50">{a.source} → {a.endpoint} | {a.count}</p></div>
              <StatusBadge status={a.status} />
            </div>
          ))}
        </div>
      )}
      {tab === "policies" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Enforced API Security Policies</h3>
          {[
            { name: "Rate Limiting", endpoints: 342, action: "429 after threshold", active: true },
            { name: "Authentication Required", endpoints: 298, action: "401 on missing token", active: true },
            { name: "Input Validation", endpoints: 256, action: "400 on malformed input", active: true },
            { name: "Response Filtering", endpoints: 180, action: "Strip sensitive fields", active: true },
            { name: "IP Blocklist", endpoints: 342, action: "Block known bad IPs", active: true },
          ].map((p) => (
            <div key={p.name} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{p.name}</p><p className="text-xs text-white/50">{p.endpoints} endpoints | {p.action}</p></div>
              <StatusBadge status="active" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
