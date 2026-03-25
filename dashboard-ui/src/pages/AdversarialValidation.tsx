import { useState } from "react";
import { RefreshCw, Shield, AlertTriangle, CheckCircle, XCircle, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "validations" | "effectiveness" | "flywheel";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "validations", label: "Validation Tests" },
  { id: "effectiveness", label: "Effectiveness" }, { id: "flywheel", label: "Data Flywheel" },
];
export default function AdversarialValidation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Adversarial Validation" subtitle="Closed-loop red/blue verification — proving defenses actually work" icon={<RefreshCw className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Tests Run (7d)" value="142" icon={<RefreshCw className="h-5 w-5" />} />
        <MetricCard title="Defenses Validated" value="89%" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Regressions Found" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Patterns Updated" value="18" icon={<TrendingUp className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Defense Validation Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ type: "Firewall Rules", tested: 34, blocked: 31, pct: 91 }, { type: "Policy Updates", tested: 28, blocked: 26, pct: 93 }, { type: "Detection Rules", tested: 42, blocked: 35, pct: 83 }].map((d) => (
              <div key={d.type} className="card-interactive p-4"><p className="text-sm text-white/60">{d.type}</p><p className={clsx("text-2xl font-bold mt-1", d.pct >= 90 ? "text-emerald-400" : "text-yellow-400")}>{d.pct}%</p><p className="text-xs text-white/40">{d.blocked}/{d.tested} attacks blocked</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "validations" && (
        <div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Technique</th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Defense</th><th className="px-4 py-3">Outcome</th><th className="px-4 py-3">Confidence</th></tr></thead>
          <tbody>{[
            { tech: "T1078 Valid Accounts", target: "prod-api", defense: "Credential Rotation", outcome: "blocked", conf: 95 },
            { tech: "T1021 Remote Services", target: "db-cluster", defense: "Network Policy", outcome: "blocked", conf: 92 },
            { tech: "T1550 Token Reuse", target: "oauth-service", defense: "Token Revocation", outcome: "bypassed", conf: 78 },
          ].map((v, i) => (
            <tr key={i} className="border-b border-white/5 hover:bg-white/5">
              <td className="px-4 py-3 text-white/90">{v.tech}</td><td className="px-4 py-3 text-white/70">{v.target}</td>
              <td className="px-4 py-3 text-white/70">{v.defense}</td><td className="px-4 py-3"><StatusBadge status={v.outcome} /></td>
              <td className="px-4 py-3 text-white/80">{v.conf}%</td>
            </tr>
          ))}</tbody></table>
        </div>
      )}
      {tab === "effectiveness" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Defense Effectiveness by Category</h3>
          {[{ cat: "Credential Controls", eff: 93, trend: "+4%" }, { cat: "Network Policies", eff: 91, trend: "+2%" }, { cat: "Detection Rules", eff: 83, trend: "-5%" }, { cat: "Config Hardening", eff: 88, trend: "+1%" }].map((e) => (
            <div key={e.cat} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{e.cat}</p><span className={clsx("text-sm font-bold", e.eff >= 90 ? "text-emerald-400" : "text-yellow-400")}>{e.eff}%</span></div>
              <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${e.eff}%` }} /></div>
              <p className="text-xs text-white/40 mt-1">Trend: <span className={e.trend.startsWith("+") ? "text-emerald-400" : "text-red-400"}>{e.trend}</span></p>
            </div>
          ))}
        </div>
      )}
      {tab === "flywheel" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Data Flywheel Metrics</h3>
          <div className="grid grid-cols-2 gap-4">
            {[{ m: "Attack Patterns (DB)", v: "1,247" }, { m: "Defense Patterns (DB)", v: "892" }, { m: "Cross-Customer Validated", v: "342" }, { m: "Flywheel Growth (30d)", v: "+18%" }].map((f) => (
              <div key={f.m} className="card-interactive p-4"><p className="text-sm text-white/60">{f.m}</p><p className="text-2xl font-bold text-white mt-1">{f.v}</p></div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
