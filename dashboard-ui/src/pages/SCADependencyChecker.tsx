import { useState } from "react";
import { Package, Shield, AlertTriangle, Bug, Scale, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "cves" | "licenses" | "outdated";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "cves", label: "CVEs" }, { id: "licenses", label: "Licenses" }, { id: "outdated", label: "Outdated" }];
export default function SCADependencyChecker() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="SCA Dependency Checker" subtitle="Software composition analysis — CVE matching, license compliance, transitive vulnerability tracking" icon={<Package className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Dependencies" value="342" icon={<Package className="h-5 w-5" />} />
      <MetricCard title="CVEs Found" value="23" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="License Issues" value="4" icon={<Scale className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Up-to-date" value="78%" icon={<RefreshCw className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk by Ecosystem</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ eco: "PyPI", deps: 156, vulns: 12, color: "text-yellow-400" }, { eco: "npm", deps: 98, vulns: 8, color: "text-yellow-400" }, { eco: "Go", deps: 54, vulns: 2, color: "text-emerald-400" }, { eco: "Maven", deps: 34, vulns: 1, color: "text-emerald-400" }].map((e) => (
        <div key={e.eco} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{e.eco}</p><p className={clsx("text-3xl font-bold mt-1", e.color)}>{e.vulns}</p><p className="text-xs text-white/40">{e.deps} packages</p></div>))}</div></div>)}
    {tab === "cves" && (<div className="space-y-3">
      {[{ pkg: "langchain@0.0.300", cve: "CVE-2024-LC001", cvss: 9.1, sev: "critical", fix: "0.1.0" },
        { pkg: "flask@2.2.0", cve: "CVE-2023-30861", cvss: 7.5, sev: "high", fix: "2.3.2" },
        { pkg: "lodash@4.17.19", cve: "CVE-2021-23337", cvss: 7.2, sev: "high", fix: "4.17.21" },
        { pkg: "requests@2.28.0", cve: "CVE-2023-32681", cvss: 6.1, sev: "medium", fix: "2.31.0" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium font-mono">{c.pkg}</p><p className="text-xs text-white/50">{c.cve} | CVSS {c.cvss} | Fix: {c.fix}</p></div><StatusBadge status={c.sev} /></div></div>))}</div>)}
    {tab === "licenses" && (<div className="space-y-3">
      {[{ pkg: "crypto-lib@3.1", license: "GPL-3.0", risk: "Copyleft infection", sev: "high" },
        { pkg: "ml-utils@1.0", license: "AGPL-3.0", risk: "Network copyleft", sev: "critical" },
        { pkg: "legacy-sdk@2.5", license: "Proprietary", risk: "Commercial restriction", sev: "medium" },
      ].map((l, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium font-mono">{l.pkg}</p><StatusBadge status={l.sev} /></div>
        <p className="text-xs text-white/50">{l.license} | {l.risk}</p></div>))}</div>)}
    {tab === "outdated" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Package</th><th className="px-4 py-3">Installed</th><th className="px-4 py-3">Latest</th><th className="px-4 py-3">Behind</th></tr></thead>
      <tbody>{[
        { pkg: "requests", installed: "2.28.0", latest: "2.31.0", behind: "3 versions" },
        { pkg: "flask", installed: "2.2.0", latest: "2.3.3", behind: "5 versions" },
        { pkg: "numpy", installed: "1.23.0", latest: "1.26.0", behind: "12 versions" },
      ].map((d, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{d.pkg}</td><td className="px-4 py-3 text-white/70">{d.installed}</td><td className="px-4 py-3 text-emerald-400">{d.latest}</td><td className="px-4 py-3 text-yellow-400">{d.behind}</td></tr>))}</tbody></table></div>)}
  </div>);
}
