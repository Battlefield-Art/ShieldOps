import { useState } from "react";
import { Package, AlertTriangle, Shield, FileCheck, GitBranch, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "sbom" | "cicd" | "signatures";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "sbom", label: "SBOM & Dependencies" },
  { id: "cicd", label: "CI/CD Security" }, { id: "signatures", label: "Artifact Signing" },
];

export default function SupplyChainSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Supply Chain Security" subtitle="SBOM generation, dependency scanning, CI/CD security, and artifact signing" icon={<Package className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Dependencies" value="1,247" icon={<Package className="h-5 w-5" />} />
        <MetricCard title="Vulnerable Deps" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Pipeline Coverage" value="94%" icon={<GitBranch className="h-5 w-5" />} />
        <MetricCard title="Signed Artifacts" value="98%" icon={<Lock className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Supply Chain Health</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ eco: "Python (pip)", deps: 423, vulns: 8 }, { eco: "JavaScript (npm)", deps: 612, vulns: 12 }, { eco: "Go", deps: 212, vulns: 3 }].map((e) => (
              <div key={e.eco} className="card-interactive p-4"><p className="text-sm text-white/60">{e.eco}</p><p className="text-2xl font-bold text-white mt-1">{e.deps} deps</p><p className="text-xs text-white/40">{e.vulns} vulnerable</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "sbom" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Package</th><th className="px-4 py-3">Version</th><th className="px-4 py-3">Ecosystem</th><th className="px-4 py-3">License</th><th className="px-4 py-3">Vulns</th><th className="px-4 py-3">Risk</th></tr></thead>
            <tbody>
              {[
                { pkg: "requests", ver: "2.31.0", eco: "pip", lic: "Apache-2.0", vulns: 1, risk: "medium" },
                { pkg: "lodash", ver: "4.17.20", eco: "npm", lic: "MIT", vulns: 2, risk: "high" },
                { pkg: "golang.org/x/net", ver: "0.17.0", eco: "go", lic: "BSD-3", vulns: 0, risk: "low" },
                { pkg: "django", ver: "4.2.7", eco: "pip", lic: "BSD-3", vulns: 1, risk: "medium" },
              ].map((d, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-cyan-400 font-mono text-sm">{d.pkg}</td>
                  <td className="px-4 py-3 text-white/70">{d.ver}</td>
                  <td className="px-4 py-3 text-white/60">{d.eco}</td>
                  <td className="px-4 py-3 text-white/60">{d.lic}</td>
                  <td className="px-4 py-3 text-white/80">{d.vulns}</td>
                  <td className="px-4 py-3"><StatusBadge status={d.risk} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "cicd" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">CI/CD Pipeline Security</h3>
          {[
            { pipeline: "ci.yml", checks: 5, passing: 5, findings: 0 },
            { pipeline: "cd-backend.yml", checks: 5, passing: 4, findings: 2 },
            { pipeline: "cd-dashboard.yml", checks: 4, passing: 4, findings: 0 },
          ].map((p) => (
            <div key={p.pipeline} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium font-mono">{p.pipeline}</p><p className="text-xs text-white/50">{p.passing}/{p.checks} security checks passing | {p.findings} findings</p></div>
              <StatusBadge status={p.findings > 0 ? "warning" : "active"} />
            </div>
          ))}
        </div>
      )}
      {tab === "signatures" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Artifact Signature Verification</h3>
          {[
            { artifact: "shieldops-api:v2.4.0", type: "Container Image", signed: true, signer: "ci-pipeline@shieldops", valid: true },
            { artifact: "shieldops-sdk-0.9.0.tar.gz", type: "Python Package", signed: true, signer: "release@shieldops", valid: true },
            { artifact: "helm-chart-0.8.0.tgz", type: "Helm Chart", signed: false, signer: "—", valid: false },
          ].map((a, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{a.artifact}</p><p className="text-xs text-white/50">{a.type} | Signer: {a.signer}</p></div>
              {a.signed ? <span className="text-xs text-emerald-400">Signed & Valid</span> : <span className="text-xs text-red-400">Unsigned</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
