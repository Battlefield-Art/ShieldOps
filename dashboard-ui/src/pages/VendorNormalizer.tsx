import { useState } from "react";
import { Layers, ArrowRightLeft, AlertTriangle, BarChart3, Globe } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";

// ── Types ────────────────────────────────────────────────────────────
type TabId = "overview" | "vendors" | "mappings" | "quality";

interface VendorStatus {
  name: string;
  eventsNormalized: number;
  completeness: number;
  unmappedFields: number;
  quality: "excellent" | "good" | "moderate" | "poor";
}

// ── Mock Data ────────────────────────────────────────────────────────
const VENDORS: VendorStatus[] = [
  { name: "CrowdStrike Falcon", eventsNormalized: 45200, completeness: 96, unmappedFields: 2, quality: "excellent" },
  { name: "Microsoft Defender", eventsNormalized: 31800, completeness: 91, unmappedFields: 5, quality: "good" },
  { name: "Wiz", eventsNormalized: 12400, completeness: 88, unmappedFields: 8, quality: "good" },
  { name: "Splunk", eventsNormalized: 89300, completeness: 94, unmappedFields: 3, quality: "excellent" },
  { name: "Elastic", eventsNormalized: 67100, completeness: 85, unmappedFields: 11, quality: "moderate" },
  { name: "Datadog", eventsNormalized: 23500, completeness: 82, unmappedFields: 14, quality: "moderate" },
  { name: "PagerDuty", eventsNormalized: 5600, completeness: 78, unmappedFields: 9, quality: "moderate" },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "vendors", label: "Vendor Status" },
  { id: "mappings", label: "Field Mappings" },
  { id: "quality", label: "Quality Metrics" },
];

const QUALITY_STYLES: Record<string, string> = {
  excellent: "text-emerald-400",
  good: "text-cyan-400",
  moderate: "text-yellow-400",
  poor: "text-red-400",
};

// ── Component ────────────────────────────────────────────────────────
export default function VendorNormalizer() {
  const [tab, setTab] = useState<TabId>("overview");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vendor Normalizer"
        subtitle="OCSF schema normalization for cross-vendor security telemetry"
        icon={<Layers className="h-6 w-6" />}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Connected Vendors" value="17" icon={<Globe className="h-5 w-5" />} />
        <MetricCard title="Events Normalized (24h)" value="274.9K" icon={<ArrowRightLeft className="h-5 w-5" />} />
        <MetricCard title="Avg Completeness" value="88%" icon={<BarChart3 className="h-5 w-5" />} />
        <MetricCard title="Unmapped Fields" value="52" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      </div>

      <div className="tab-bar">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">OCSF Normalization Summary</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Security Findings</p>
              <p className="text-2xl font-bold text-white mt-1">156.2K</p>
              <p className="text-xs text-white/40">OCSF Category 2001</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Identity Activity</p>
              <p className="text-2xl font-bold text-white mt-1">72.4K</p>
              <p className="text-xs text-white/40">OCSF Category 3001</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Network Activity</p>
              <p className="text-2xl font-bold text-white mt-1">46.3K</p>
              <p className="text-xs text-white/40">OCSF Category 4001</p>
            </div>
          </div>
        </div>
      )}

      {tab === "vendors" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-white/50">
                <th className="px-4 py-3">Vendor</th>
                <th className="px-4 py-3">Events (24h)</th>
                <th className="px-4 py-3">Completeness</th>
                <th className="px-4 py-3">Unmapped</th>
                <th className="px-4 py-3">Quality</th>
              </tr>
            </thead>
            <tbody>
              {VENDORS.map((v) => (
                <tr key={v.name} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-white/90 font-medium">{v.name}</td>
                  <td className="px-4 py-3 text-white/80">{v.eventsNormalized.toLocaleString()}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-white/10 rounded-full max-w-[100px]">
                        <div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${v.completeness}%` }} />
                      </div>
                      <span className="text-white/70">{v.completeness}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-white/70">{v.unmappedFields}</td>
                  <td className={clsx("px-4 py-3 capitalize font-medium", QUALITY_STYLES[v.quality])}>{v.quality}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "mappings" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">OCSF Field Mapping Coverage</h3>
          <div className="space-y-3">
            {[
              { category: "Identity Fields", mapped: 42, total: 45 },
              { category: "Network Fields", mapped: 38, total: 48 },
              { category: "Endpoint Fields", mapped: 35, total: 40 },
              { category: "Cloud Fields", mapped: 28, total: 36 },
              { category: "Application Fields", mapped: 22, total: 30 },
            ].map((m) => (
              <div key={m.category} className="card-interactive p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-white/90 font-medium">{m.category}</p>
                  <span className="text-sm text-white/60">{m.mapped}/{m.total}</span>
                </div>
                <div className="h-2 bg-white/10 rounded-full">
                  <div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${(m.mapped / m.total) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "quality" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Normalization Quality Trends</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Validation Pass Rate</p>
              <p className="text-2xl font-bold text-emerald-400 mt-1">97.3%</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Schema Errors (24h)</p>
              <p className="text-2xl font-bold text-yellow-400 mt-1">142</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Enrichment Coverage</p>
              <p className="text-2xl font-bold text-cyan-400 mt-1">84%</p>
            </div>
            <div className="card-interactive p-4">
              <p className="text-sm text-white/60">Avg Normalization Latency</p>
              <p className="text-2xl font-bold text-white mt-1">12ms</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
