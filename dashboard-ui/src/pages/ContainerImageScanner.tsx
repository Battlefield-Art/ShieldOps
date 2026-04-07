import { useState } from "react";
import { Container, Bug, Layers, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "images" | "vulnerabilities" | "compliance";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "images", label: "Images" }, { id: "vulnerabilities", label: "Vulnerabilities" }, { id: "compliance", label: "Compliance" }];
export default function ContainerImageScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Container Image Scanner" subtitle="Scan container images for vulnerabilities, misconfigurations, secrets, and compliance violations" icon={<Container className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Images Scanned" value="67" icon={<Container className="h-5 w-5" />} />
      <MetricCard title="Vulnerabilities" value="189" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Layers Analyzed" value="402" icon={<Layers className="h-5 w-5" />} />
      <MetricCard title="Compliant" value="82%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Vulnerability by Severity</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ sev: "Critical", count: 8, color: "text-red-400" }, { sev: "High", count: 34, color: "text-yellow-400" }, { sev: "Medium", count: 89, color: "text-yellow-400" }, { sev: "Low", count: 58, color: "text-white/60" }].map((s) => (
        <div key={s.sev} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.sev}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "images" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Image</th><th className="px-4 py-3">Tag</th><th className="px-4 py-3">Vulns</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { img: "shieldops/api", tag: "v2.1.0", vulns: 12, status: "warning" },
        { img: "shieldops/worker", tag: "v2.1.0", vulns: 3, status: "healthy" },
        { img: "shieldops/agent", tag: "latest", vulns: 28, status: "critical" },
        { img: "postgres", tag: "15.4", vulns: 5, status: "warning" },
      ].map((i, idx) => (<tr key={idx} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{i.img}</td><td className="px-4 py-3 text-white/70">{i.tag}</td><td className="px-4 py-3 text-white/90">{i.vulns}</td><td className="px-4 py-3"><StatusBadge status={i.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "vulnerabilities" && (<div className="space-y-3">
      {[{ pkg: "openssl 1.1.1k", cve: "CVE-2023-5678", cvss: 7.5, sev: "high", fixable: true },
        { pkg: "curl 7.88.0", cve: "CVE-2023-46218", cvss: 6.5, sev: "medium", fixable: true },
        { pkg: "python3.12", cve: "CVE-2023-PY001", cvss: 5.3, sev: "medium", fixable: true },
      ].map((v, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium">{v.pkg}</p><p className="text-xs text-white/50">{v.cve} | CVSS {v.cvss} | {v.fixable ? "Fixable" : "No fix"}</p></div><StatusBadge status={v.sev} /></div></div>))}</div>)}
    {tab === "compliance" && (<div className="space-y-3">
      {[{ check: "CIS-4.1: Non-root user", status: "warning", desc: "3 images run as root" },
        { check: "CIS-4.6: HEALTHCHECK", status: "pass", desc: "All images have healthchecks" },
        { check: "CIS-4.10: No secrets in images", status: "fail", desc: "2 images contain secrets" },
        { check: "CIS-4.2: Trusted base images", status: "pass", desc: "All from approved registry" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.check}</p><p className="text-xs text-white/50">{c.desc}</p></div><StatusBadge status={c.status} /></div>))}</div>)}
  </div>);
}
