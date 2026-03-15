import { Shield, Database, ShieldBan, Rss, Radar } from "lucide-react";
import MetricCard from "../components/MetricCard";

type Confidence = "confirmed" | "probable" | "unverified";

const CONFIDENCE_CLASSES: Record<Confidence, string> = {
  confirmed: "bg-green-500/10 text-green-400 ring-green-500/20",
  probable: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  unverified: "bg-gray-500/10 text-gray-400 ring-gray-500/20",
};

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
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Threat Intelligence</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <Radar className="h-4 w-4" /> Run Intel Scan
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total IOCs" value={1_247} icon={<Database className="h-5 w-5" />} change={8.2} />
        <MetricCard label="Actionable" value={312} icon={<Shield className="h-5 w-5" />} change={3.1} />
        <MetricCard label="Blocked" value={189} icon={<ShieldBan className="h-5 w-5" />} change={12.5} />
        <MetricCard label="Feed Sources" value={9} icon={<Rss className="h-5 w-5" />} change={0} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Recent Threat Indicators</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Value</th>
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="px-5 py-3 font-medium">Source</th>
                <th className="px-5 py-3 font-medium">Confidence</th>
                <th className="px-5 py-3 font-medium">Relevance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_INDICATORS.map((ioc, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-mono text-xs text-gray-100">{ioc.value}</td>
                  <td className="px-5 py-3">{ioc.type}</td>
                  <td className="px-5 py-3">{ioc.source}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${CONFIDENCE_CLASSES[ioc.confidence]}`}>
                      {ioc.confidence}
                    </span>
                  </td>
                  <td className="px-5 py-3">{ioc.relevance}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
