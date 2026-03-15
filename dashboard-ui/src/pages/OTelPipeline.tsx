import { Activity, Server, Gauge, Clock, Search, Settings } from "lucide-react";
import MetricCard from "../components/MetricCard";
import StatusBadge from "../components/StatusBadge";

const MOCK_SERVICES = [
  { name: "payment-service", instrumented: true, signals: "Traces, Metrics, Logs", collector: "otel-col-01", status: "healthy" },
  { name: "auth-gateway", instrumented: true, signals: "Traces, Metrics", collector: "otel-col-01", status: "healthy" },
  { name: "order-processor", instrumented: false, signals: "Metrics", collector: "otel-col-02", status: "degraded" },
  { name: "user-api", instrumented: true, signals: "Traces, Logs", collector: "otel-col-02", status: "healthy" },
  { name: "notification-svc", instrumented: false, signals: "—", collector: "—", status: "offline" },
  { name: "search-indexer", instrumented: true, signals: "Traces, Metrics, Logs", collector: "otel-col-03", status: "healthy" },
  { name: "billing-engine", instrumented: true, signals: "Traces, Metrics", collector: "otel-col-03", status: "warning" },
];

export default function OTelPipeline() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">OTel Pipeline Management</h1>
        <div className="flex gap-3">
          <button className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm font-medium text-gray-200 hover:bg-gray-700">
            <Search className="h-4 w-4" /> Discover Services
          </button>
          <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
            <Settings className="h-4 w-4" /> Configure Collector
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total Collectors" value={3} icon={<Server className="h-5 w-5" />} change={0} />
        <MetricCard label="Healthy %" value="85.7%" icon={<Activity className="h-5 w-5" />} change={2.3} />
        <MetricCard label="Data Throughput" value="1.4 GB/min" icon={<Gauge className="h-5 w-5" />} change={5.1} />
        <MetricCard label="Avg Latency" value="12 ms" icon={<Clock className="h-5 w-5" />} change={-1.8} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Discovered Services</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Service</th>
                <th className="px-5 py-3 font-medium">Instrumented</th>
                <th className="px-5 py-3 font-medium">Signal Types</th>
                <th className="px-5 py-3 font-medium">Collector</th>
                <th className="px-5 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_SERVICES.map((svc) => (
                <tr key={svc.name} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-medium text-gray-100">{svc.name}</td>
                  <td className="px-5 py-3">
                    <span className={svc.instrumented ? "text-green-400" : "text-gray-500"}>
                      {svc.instrumented ? "Yes" : "No"}
                    </span>
                  </td>
                  <td className="px-5 py-3">{svc.signals}</td>
                  <td className="px-5 py-3 font-mono text-xs">{svc.collector}</td>
                  <td className="px-5 py-3"><StatusBadge status={svc.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
