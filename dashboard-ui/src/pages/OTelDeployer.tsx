import { useState } from "react";
import { Server, Rocket, Clock, RotateCcw, ClipboardList } from "lucide-react";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type DeployStatus = "running" | "pending" | "failed" | "rolled-back";

const MOCK_DEPLOYMENTS = [
  { cluster: "prod-us-east", namespace: "monitoring", target: "daemonset", strategy: "rolling", healthyPods: "48/48", status: "running" as DeployStatus },
  { cluster: "prod-eu-west", namespace: "monitoring", target: "daemonset", strategy: "rolling", healthyPods: "32/32", status: "running" as DeployStatus },
  { cluster: "staging-us", namespace: "otel-system", target: "deployment", strategy: "blue-green", healthyPods: "3/3", status: "running" as DeployStatus },
  { cluster: "prod-ap-south", namespace: "monitoring", target: "daemonset", strategy: "canary", healthyPods: "0/24", status: "pending" as DeployStatus },
  { cluster: "dev-local", namespace: "default", target: "sidecar", strategy: "recreate", healthyPods: "5/5", status: "running" as DeployStatus },
  { cluster: "prod-us-west", namespace: "monitoring", target: "deployment", strategy: "rolling", healthyPods: "0/6", status: "failed" as DeployStatus },
];

export default function OTelDeployer() {
  const [planning, setPlanning] = useState(false);
  const handlePlan = () => { setPlanning(true); setTimeout(() => setPlanning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="OTel Deployment Orchestrator"
        action={{
          label: "Plan Deployment",
          onClick: handlePlan,
          icon: <ClipboardList className="h-4 w-4" />,
          loading: planning,
        }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Clusters" value={12} icon={<Server className="h-5 w-5" />} change={0} />
        <MetricCard label="Deployed Collectors" value={164} icon={<Rocket className="h-5 w-5" />} change={6.8} />
        <MetricCard label="Pending Deploys" value={3} icon={<Clock className="h-5 w-5" />} change={-1.5} />
        <MetricCard label="Rollback Available" value={8} icon={<RotateCcw className="h-5 w-5" />} change={0} />
      </div>

      <div className="overflow-hidden rounded-xl border border-white/[0.06] bg-surface-2 shadow-card">
        <div className="border-b border-white/[0.04] px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-50">Deployment Status</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.04] text-left text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3.5 font-medium">Cluster</th>
                <th className="px-5 py-3.5 font-medium">Namespace</th>
                <th className="px-5 py-3.5 font-medium">Target</th>
                <th className="px-5 py-3.5 font-medium">Strategy</th>
                <th className="px-5 py-3.5 font-medium">Healthy Pods</th>
                <th className="px-5 py-3.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {MOCK_DEPLOYMENTS.map((d, i) => (
                <tr key={i} className="text-gray-300 hover:bg-surface-3/30">
                  <td className="px-5 py-3.5 font-mono text-xs text-gray-100">{d.cluster}</td>
                  <td className="px-5 py-3.5">{d.namespace}</td>
                  <td className="px-5 py-3.5">{d.target}</td>
                  <td className="px-5 py-3.5">{d.strategy}</td>
                  <td className="px-5 py-3.5 font-mono text-xs">{d.healthyPods}</td>
                  <td className="px-5 py-3.5">
                    <StatusBadge status={d.status === "rolled-back" ? "rolled_back" : d.status} />
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
