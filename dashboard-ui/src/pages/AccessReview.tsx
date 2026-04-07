import { useState } from "react";
import { ClipboardCheck, Users, AlertTriangle, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "campaigns" | "violations" | "certifications";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "campaigns", label: "Campaigns" },
  { id: "violations", label: "Violations" }, { id: "certifications", label: "Certifications" },
];
export default function AccessReview() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Access Review" subtitle="Periodic access review campaigns for SOC 2 and HIPAA compliance" icon={<ClipboardCheck className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Campaigns" value="2" icon={<ClipboardCheck className="h-5 w-5" />} />
        <MetricCard title="Entitlements Reviewed" value="1,247" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Violations Found" value="34" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Completion Rate" value="87%" icon={<CheckCircle className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Access Review Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ label: "Certified", count: 1087, pct: 87 }, { label: "Revoked", count: 98, pct: 8 }, { label: "Pending", count: 62, pct: 5 }].map((s) => (
              <div key={s.label} className="card-interactive p-4"><p className="text-sm text-white/60">{s.label}</p><p className="text-2xl font-bold text-white mt-1">{s.count}</p><p className="text-xs text-white/40">{s.pct}% of total</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "campaigns" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Campaigns</h3>
          {[{ name: "Q1-2026 SOC 2 Review", status: "active", entitlements: 847, completed: 738, due: "Apr 15" },
            { name: "HIPAA Annual Review", status: "active", entitlements: 400, completed: 342, due: "Apr 30" },
            { name: "Q4-2025 Review", status: "closed", entitlements: 1200, completed: 1200, due: "Completed" },
          ].map((c) => (
            <div key={c.name} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{c.name}</p><StatusBadge status={c.status} /></div>
              <div className="h-2 bg-white/10 rounded-full mb-2"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${(c.completed / c.entitlements) * 100}%` }} /></div>
              <p className="text-xs text-white/50">{c.completed}/{c.entitlements} reviewed | Due: {c.due}</p>
            </div>
          ))}
        </div>
      )}
      {tab === "violations" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Access Violations</h3>
          {[{ type: "Excessive Access", identity: "svc-admin (SA)", resource: "production-db", desc: "Full admin on DB — only reads needed", sev: "critical" },
            { type: "Separation of Duties", identity: "deploy-bot (SA)", resource: "IAM + prod-deploy", desc: "IAM modify + production deploy = SoD violation", sev: "high" },
            { type: "Orphaned Entitlement", identity: "former-contractor", resource: "code-repo", desc: "Former contractor still has write access", sev: "high" },
          ].map((v, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{v.type}: <span className="text-cyan-400">{v.identity}</span></p><p className="text-xs text-white/50">{v.resource} — {v.desc}</p></div>
              <StatusBadge status={v.sev} />
            </div>
          ))}
        </div>
      )}
      {tab === "certifications" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Review Outcomes</h3>
          <div className="grid grid-cols-2 gap-4">
            {[{ m: "Auto-Certified (low risk)", v: "642" }, { m: "Manually Reviewed", v: "445" }, { m: "Access Revoked", v: "98" }, { m: "Escalated to Manager", v: "34" }].map((o) => (
              <div key={o.m} className="card-interactive p-4"><p className="text-sm text-white/60">{o.m}</p><p className="text-2xl font-bold text-white mt-1">{o.v}</p></div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
