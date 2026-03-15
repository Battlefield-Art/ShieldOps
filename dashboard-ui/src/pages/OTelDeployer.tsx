import { Server, Rocket, Clock, RotateCcw, ClipboardList } from "lucide-react";
import MetricCard from "../components/MetricCard";

type DeployStatus = "running" | "pending" | "failed" | "rolled-back";

const STATUS_CLASSES: Record<DeployStatus, string> = {
  running: "bg-green-500/10 text-green-400 ring-green-500/20",
  pending: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  failed: "bg-red-500/10 text-red-400 ring-red-500/20",
  "rolled-back": "bg-gray-500/10 text-gray-400 ring-gray-500/20",
};

const MOCK_DEPLOYMENTS = [
  { cluster: "prod-us-east", namespace: "monitoring", target: "daemonset", strategy: "rolling", healthyPods: "48/48", status: "running" as DeployStatus },
  { cluster: "prod-eu-west", namespace: "monitoring", target: "daemonset", strategy: "rolling", healthyPods: "32/32", status: "running" as DeployStatus },
  { cluster: "staging-us", namespace: "otel-system", target: "deployment", strategy: "blue-green", healthyPods: "3/3", status: "running" as DeployStatus },
  { cluster: "prod-ap-south", namespace: "monitoring", target: "daemonset", strategy: "canary", healthyPods: "0/24", status: "pending" as DeployStatus },
  { cluster: "dev-local", namespace: "default", target: "sidecar", strategy: "recreate", healthyPods: "5/5", status: "running" as DeployStatus },
  { cluster: "prod-us-west", namespace: "monitoring", target: "deployment", strategy: "rolling", healthyPods: "0/6", status: "failed" as DeployStatus },
];

export default function OTelDeployer() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">OTel Deployment Orchestrator</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <ClipboardList className="h-4 w-4" /> Plan Deployment
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Clusters" value={12} icon={<Server className="h-5 w-5" />} change={0} />
        <MetricCard label="Deployed Collectors" value={164} icon={<Rocket className="h-5 w-5" />} change={6.8} />
        <MetricCard label="Pending Deploys" value={3} icon={<Clock className="h-5 w-5" />} change={-1.5} />
        <MetricCard label="Rollback Available" value={8} icon={<RotateCcw className="h-5 w-5" />} change={0} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Deployment Status</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Cluster</th>
                <th className="px-5 py-3 font-medium">Namespace</th>
                <th className="px-5 py-3 font-medium">Target</th>
                <th className="px-5 py-3 font-medium">Strategy</th>
                <th className="px-5 py-3 font-medium">Healthy Pods</th>
                <th className="px-5 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_DEPLOYMENTS.map((d, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-mono text-xs text-gray-100">{d.cluster}</td>
                  <td className="px-5 py-3">{d.namespace}</td>
                  <td className="px-5 py-3">{d.target}</td>
                  <td className="px-5 py-3">{d.strategy}</td>
                  <td className="px-5 py-3 font-mono text-xs">{d.healthyPods}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_CLASSES[d.status]}`}>
                      {d.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
