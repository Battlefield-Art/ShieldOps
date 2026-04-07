import { useState } from "react";
import { Users, AlertTriangle, Key, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "accounts" | "anomalies" | "sharing";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "accounts", label: "Service Accounts" },
  { id: "anomalies", label: "Usage Anomalies" }, { id: "sharing", label: "Credential Sharing" },
];
export default function ServiceAccountTracker() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Service Account Tracker" subtitle="Inventory, monitor, and govern service accounts across all clouds" icon={<Users className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Accounts" value="342" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Orphaned" value="18" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Shared Credentials" value="7" icon={<Key className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Dormant (>90d)" value="43" icon={<Clock className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Service Account Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {[{ cloud: "AWS IAM", count: 124, orphaned: 8 }, { cloud: "GCP IAM", count: 78, orphaned: 4 }, { cloud: "Azure AD", count: 56, orphaned: 3 }, { cloud: "K8s SA", count: 62, orphaned: 2 }, { cloud: "GitHub", count: 22, orphaned: 1 }].map((c) => (
              <div key={c.cloud} className="card-interactive p-3 text-center"><p className="text-xs text-white/50">{c.cloud}</p><p className="text-xl font-bold text-white">{c.count}</p><p className="text-xs text-red-400">{c.orphaned} orphaned</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "accounts" && (
        <div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Account</th><th className="px-4 py-3">Cloud</th><th className="px-4 py-3">Owner</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Inactive</th><th className="px-4 py-3">Keys</th><th className="px-4 py-3">Risk</th></tr></thead>
          <tbody>{[
            { name: "ci-deployer", cloud: "AWS", owner: "unknown", status: "orphaned", days: 180, keys: 3, risk: 88 },
            { name: "monitoring-sa", cloud: "GCP", owner: "platform-team", status: "active", days: 0, keys: 1, risk: 12 },
            { name: "legacy-backup", cloud: "AWS", owner: "unknown", status: "dormant", days: 342, keys: 2, risk: 92 },
            { name: "k8s-scheduler", cloud: "K8s", owner: "infra-team", status: "active", days: 0, keys: 1, risk: 8 },
          ].map((a, i) => (
            <tr key={i} className="border-b border-white/5 hover:bg-white/5">
              <td className="px-4 py-3 text-cyan-400 font-mono text-sm">{a.name}</td><td className="px-4 py-3 text-white/70">{a.cloud}</td>
              <td className="px-4 py-3 text-white/60">{a.owner}</td><td className="px-4 py-3"><StatusBadge status={a.status} /></td>
              <td className="px-4 py-3 text-white/70">{a.days}d</td><td className="px-4 py-3 text-white/80">{a.keys}</td>
              <td className="px-4 py-3"><span className={clsx("font-bold", a.risk > 70 ? "text-red-400" : a.risk > 40 ? "text-yellow-400" : "text-emerald-400")}>{a.risk}%</span></td>
            </tr>
          ))}</tbody></table>
        </div>
      )}
      {tab === "anomalies" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Usage Anomalies (7d)</h3>
          {[{ account: "ci-deployer", type: "Geo-impossible login", desc: "Used from US-East and EU-West within 3 minutes", sev: "critical" },
            { account: "data-export-sa", type: "Unusual volume", desc: "10x normal data export volume at 3am", sev: "high" },
          ].map((a, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{a.type}: <span className="font-mono text-cyan-400">{a.account}</span></p><p className="text-xs text-white/50">{a.desc}</p></div>
              <StatusBadge status={a.sev} />
            </div>
          ))}
        </div>
      )}
      {tab === "sharing" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Credential Sharing Detections</h3>
          {[{ account: "deploy-key-prod", method: "IP Overlap", shared: 3, risk: "high" },
            { account: "api-service-key", method: "Concurrent Use", shared: 2, risk: "medium" },
          ].map((s, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium font-mono">{s.account}</p><p className="text-xs text-white/50">Detection: {s.method} | Shared with {s.shared} identities</p></div>
              <StatusBadge status={s.risk} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
