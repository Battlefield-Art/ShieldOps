import { Server, HeartPulse, GitCommitHorizontal, Cpu, Rocket } from "lucide-react";
import MetricCard from "../components/MetricCard";

type Mode = "agent" | "gateway" | "sidecar";
type Status = "running" | "degraded" | "stopped";

const STATUS_CLASSES: Record<Status, string> = {
  running: "bg-green-500/10 text-green-400 ring-green-500/20",
  degraded: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  stopped: "bg-red-500/10 text-red-400 ring-red-500/20",
};

const MOCK_COLLECTORS = [
  { name: "otel-agent-us-east-1", namespace: "monitoring", mode: "agent" as Mode, status: "running" as Status, cpu: 12, memMb: 256, configHash: "a3f2b8c1" },
  { name: "otel-gw-primary", namespace: "otel-system", mode: "gateway" as Mode, status: "running" as Status, cpu: 34, memMb: 512, configHash: "d4e5f6a7" },
  { name: "otel-sidecar-checkout", namespace: "commerce", mode: "sidecar" as Mode, status: "degraded" as Status, cpu: 68, memMb: 128, configHash: "b8c9d0e1" },
  { name: "otel-agent-eu-west-1", namespace: "monitoring", mode: "agent" as Mode, status: "running" as Status, cpu: 18, memMb: 310, configHash: "f2a3b4c5" },
  { name: "otel-gw-failover", namespace: "otel-system", mode: "gateway" as Mode, status: "stopped" as Status, cpu: 0, memMb: 0, configHash: "e1f2a3b4" },
  { name: "otel-sidecar-payments", namespace: "commerce", mode: "sidecar" as Mode, status: "running" as Status, cpu: 22, memMb: 96, configHash: "c5d6e7f8" },
];

export default function OTelCollectorManager() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">OTel Collector Management</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <Rocket className="h-4 w-4" /> Deploy Collector
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total Collectors" value={48} icon={<Server className="h-5 w-5" />} change={4.2} />
        <MetricCard label="Healthy %" value="95.8%" icon={<HeartPulse className="h-5 w-5" />} change={1.3} />
        <MetricCard label="Config Version" value="v3.12" icon={<GitCommitHorizontal className="h-5 w-5" />} change={0} />
        <MetricCard label="Avg CPU Usage" value="24%" icon={<Cpu className="h-5 w-5" />} change={-2.1} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Collector Fleet</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Collector Name</th>
                <th className="px-5 py-3 font-medium">Namespace</th>
                <th className="px-5 py-3 font-medium">Mode</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">CPU %</th>
                <th className="px-5 py-3 font-medium">Memory MB</th>
                <th className="px-5 py-3 font-medium">Config Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_COLLECTORS.map((c, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-mono text-xs text-gray-100">{c.name}</td>
                  <td className="px-5 py-3">{c.namespace}</td>
                  <td className="px-5 py-3">{c.mode}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_CLASSES[c.status]}`}>
                      {c.status}
                    </span>
                  </td>
                  <td className="px-5 py-3">{c.cpu}</td>
                  <td className="px-5 py-3">{c.memMb}</td>
                  <td className="px-5 py-3 font-mono text-xs">{c.configHash}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
