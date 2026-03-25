import { useState } from "react";
import { Container, Shield, AlertTriangle, Bug, Activity, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "vulnerabilities" | "runtime" | "admission";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "vulnerabilities", label: "Image Vulns" },
  { id: "runtime", label: "Runtime Threats" }, { id: "admission", label: "Admission Control" },
];

export default function ContainerSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Container Security" subtitle="Image scanning, K8s runtime protection, and admission control" icon={<Container className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Images Scanned" value="142" icon={<Container className="h-5 w-5" />} />
        <MetricCard title="Critical CVEs" value="7" icon={<Bug className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Runtime Threats" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Admission Denials" value="12" icon={<Lock className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Container Security Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ label: "Image Health", value: "89%", sub: "135/142 images clean" }, { label: "Runtime Protection", value: "Active", sub: "12 namespaces monitored" }, { label: "Admission Policy", value: "Enforcing", sub: "No latest tags, no root" }].map((s) => (
              <div key={s.label} className="card-interactive p-4"><p className="text-sm text-white/60">{s.label}</p><p className="text-2xl font-bold text-white mt-1">{s.value}</p><p className="text-xs text-white/40 mt-1">{s.sub}</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "vulnerabilities" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Image</th><th className="px-4 py-3">CVE</th><th className="px-4 py-3">Package</th><th className="px-4 py-3">CVSS</th><th className="px-4 py-3">Severity</th><th className="px-4 py-3">Fix</th></tr></thead>
            <tbody>
              {[
                { image: "api-server:v2.4", cve: "CVE-2024-3094", pkg: "xz-utils", cvss: 10.0, sev: "critical", fix: "5.6.1-r2" },
                { image: "worker:latest", cve: "CVE-2024-21626", pkg: "runc", cvss: 8.6, sev: "critical", fix: "1.1.12" },
                { image: "nginx:1.24", cve: "CVE-2024-1234", pkg: "openssl", cvss: 7.5, sev: "high", fix: "1.1.1l" },
              ].map((v, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 font-mono text-xs text-cyan-400">{v.image}</td>
                  <td className="px-4 py-3 text-white/80">{v.cve}</td>
                  <td className="px-4 py-3 text-white/70">{v.pkg}</td>
                  <td className="px-4 py-3"><span className={clsx("font-bold", v.cvss >= 9 ? "text-red-400" : "text-yellow-400")}>{v.cvss}</span></td>
                  <td className="px-4 py-3"><StatusBadge status={v.sev} /></td>
                  <td className="px-4 py-3 text-emerald-400 text-xs">{v.fix}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "runtime" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Runtime Threat Detections</h3>
          {[
            { threat: "Privilege Escalation", pod: "api-pod-abc", ns: "production", desc: "Container attempted nsenter into host PID namespace", sev: "critical" },
            { threat: "Crypto Mining", pod: "worker-xyz", ns: "staging", desc: "xmrig process detected in container", sev: "high" },
            { threat: "Reverse Shell", pod: "debug-pod-01", ns: "default", desc: "Outbound connection to known C2 IP", sev: "critical" },
          ].map((t, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{t.threat}</p><p className="text-xs text-white/50">{t.pod} ({t.ns}) — {t.desc}</p></div>
              <StatusBadge status={t.sev} />
            </div>
          ))}
        </div>
      )}
      {tab === "admission" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Admission Policy Decisions (24h)</h3>
          {[
            { policy: "No :latest tags", decisions: 342, denied: 8, pct: "2.3%" },
            { policy: "No privileged containers", decisions: 342, denied: 3, pct: "0.9%" },
            { policy: "Resource limits required", decisions: 342, denied: 1, pct: "0.3%" },
            { policy: "No root user", decisions: 342, denied: 0, pct: "0%" },
          ].map((a) => (
            <div key={a.policy} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{a.policy}</p><p className="text-xs text-white/50">{a.decisions} evaluated | {a.denied} denied ({a.pct})</p></div>
              <StatusBadge status={a.denied > 0 ? "warning" : "active"} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
