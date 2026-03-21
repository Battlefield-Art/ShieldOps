import { useState } from "react";
import { Shield, Database, ShieldBan, Rss, Radar } from "lucide-react";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

const MOCK_INDICATORS = [
  { value: "185.220.101.34", type: "IP", source: "AlienVault OTX", confidence: "confirmed" as Confidence, relevance: "High" },
  { value: "malware-c2.evil.com", type: "Domain", source: "Mandiant", confidence: "confirmed" as Confidence, relevance: "Critical" },
  { value: "a3f2b8c1d9e4...7f6a", type: "SHA256", source: "VirusTotal", confidence: "probable" as Confidence, relevance: "Medium" },
  { value: "10.0.0.0/8 scanner", type: "IP Range", source: "Internal", confidence: "unverified" as Confidence, relevance: "Low" },
  { value: "phish-login.net", type: "Domain", source: "PhishTank", confidence: "confirmed" as Confidence, relevance: "High" },
  { value: "d4e5f6a7b8c9...1234", type: "MD5", source: "MISP", confidence: "probable" as Confidence, relevance: "Medium" },
  { value: "203.0.113.42", type: "IP", source: "AbuseIPDB", confidence: "unverified" as Confidence, relevance: "Low" },
];

export default function ThreatIntel() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Intelligence"
        action={{ label: "Run Intel Scan", onClick: handleClick, icon: <Radar className="h-4 w-4" />, loading: running }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total IOCs" value={1_247} icon={<Database className="h-5 w-5" />} change={8.2} />
        <MetricCard label="Actionable" value={312} icon={<Shield className="h-5 w-5" />} change={3.1} />
        <MetricCard label="Blocked" value={189} icon={<ShieldBan className="h-5 w-5" />} change={12.5} />
        <MetricCard label="Feed Sources" value={9} icon={<Rss className="h-5 w-5" />} change={0} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <div className="border-b border-gray-800/60 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-50">Recent Threat Indicators</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3.5 font-medium">Value</th>
                <th className="px-5 py-3.5 font-medium">Type</th>
                <th className="px-5 py-3.5 font-medium">Source</th>
                <th className="px-5 py-3.5 font-medium">Confidence</th>
                <th className="px-5 py-3.5 font-medium">Relevance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {MOCK_INDICATORS.map((ioc, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/30">
                  <td className="px-5 py-3.5 font-mono text-xs text-gray-100">{ioc.value}</td>
                  <td className="px-5 py-3.5">{ioc.type}</td>
                  <td className="px-5 py-3.5">{ioc.source}</td>
                  <td className="px-5 py-3.5">
                    <StatusBadge
                      status={ioc.confidence}
                      variant={ioc.confidence === "confirmed" ? "success" : ioc.confidence === "probable" ? "warning" : "neutral"}
                    />
                  </td>
                  <td className="px-5 py-3.5">{ioc.relevance}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
