import { useState } from "react";
import { Database, Shield, Tag, AlertTriangle, FileSearch, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "regulations" | "labels";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "findings", label: "Sensitive Data" },
  { id: "regulations", label: "Regulatory Mapping" }, { id: "labels", label: "Labels" },
];
export default function DataClassification() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Data Classification" subtitle="Automated data sensitivity classification for DLP and compliance" icon={<Tag className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Assets Scanned" value="156" icon={<Database className="h-5 w-5" />} />
        <MetricCard title="Sensitive Findings" value="847" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Regulations Mapped" value="5" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Labels Applied" value="94%" icon={<Tag className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Sensitivity Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {[{ level: "Top Secret", count: 12, color: "text-red-400" }, { level: "Confidential", count: 89, color: "text-orange-400" }, { level: "Internal", count: 234, color: "text-yellow-400" }, { level: "Public", count: 156, color: "text-emerald-400" }, { level: "Unclassified", count: 356, color: "text-white/50" }].map((l) => (
              <div key={l.level} className="card-interactive p-3 text-center"><p className="text-xs text-white/50">{l.level}</p><p className={clsx("text-2xl font-bold mt-1", l.color)}>{l.count}</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "findings" && (
        <div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Category</th><th className="px-4 py-3">Level</th><th className="px-4 py-3">Column/Path</th><th className="px-4 py-3">Confidence</th></tr></thead>
          <tbody>{[
            { asset: "rds-users", cat: "PII", level: "confidential", col: "users.ssn", conf: 98 },
            { asset: "s3-medical-records", cat: "PHI", level: "top_secret", col: "records/*.json", conf: 96 },
            { asset: "postgres-payments", cat: "PCI", level: "confidential", col: "cards.number", conf: 99 },
            { asset: "gcs-exports", cat: "IP", level: "internal", col: "models/weights.bin", conf: 82 },
          ].map((f, i) => (
            <tr key={i} className="border-b border-white/5 hover:bg-white/5">
              <td className="px-4 py-3 font-mono text-xs text-cyan-400">{f.asset}</td><td className="px-4 py-3 text-white/80">{f.cat}</td>
              <td className="px-4 py-3"><StatusBadge status={f.level} /></td><td className="px-4 py-3 text-white/60 font-mono text-xs">{f.col}</td>
              <td className="px-4 py-3 text-white/80">{f.conf}%</td>
            </tr>
          ))}</tbody></table>
        </div>
      )}
      {tab === "regulations" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Regulatory Coverage</h3>
          {[{ reg: "GDPR", findings: 234, compliant: 89 }, { reg: "HIPAA", findings: 156, compliant: 92 }, { reg: "PCI DSS", findings: 89, compliant: 96 }, { reg: "CCPA", findings: 178, compliant: 85 }, { reg: "SOX", findings: 45, compliant: 91 }].map((r) => (
            <div key={r.reg} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{r.reg}</p><span className={clsx("font-bold", r.compliant >= 90 ? "text-emerald-400" : "text-yellow-400")}>{r.compliant}%</span></div>
              <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${r.compliant}%` }} /></div>
              <p className="text-xs text-white/40 mt-1">{r.findings} findings mapped</p>
            </div>
          ))}
        </div>
      )}
      {tab === "labels" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Label Enforcement Status</h3>
          {[{ type: "Databases", labeled: 42, total: 45 }, { type: "S3/GCS Buckets", labeled: 89, total: 92 }, { type: "File Shares", labeled: 12, total: 19 }].map((l) => (
            <div key={l.type} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{l.type}</p><span className="text-sm text-white/60">{l.labeled}/{l.total}</span></div>
              <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${(l.labeled / l.total) * 100}%` }} /></div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
