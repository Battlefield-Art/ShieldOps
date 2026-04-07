import { useState } from "react";
import { Eye, AlertTriangle, Shield, DollarSign, Server } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "assets" | "traffic" | "governance";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "assets", label: "Discovered Assets" },
  { id: "traffic", label: "AI Traffic" },
  { id: "governance", label: "Governance Plan" },
];

export default function ShadowAIDiscovery() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Shadow AI Discovery" subtitle="Discover unmanaged AI agents, rogue MCP servers, and unauthorized model connections" icon={<Eye className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="AI Assets Found" value="34" icon={<Server className="h-5 w-5" />} />
        <MetricCard title="Unmanaged / Shadow" value="11" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Est. Monthly Cost" value="$14.2K" icon={<DollarSign className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Managed Coverage" value="68%" icon={<Shield className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">AI Asset Inventory</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ type: "LLM API Clients", managed: 12, shadow: 5, cost: "$8.4K" }, { type: "MCP Servers", managed: 6, shadow: 3, cost: "$2.1K" }, { type: "RAG Pipelines", managed: 5, shadow: 3, cost: "$3.7K" }].map((a) => (
              <div key={a.type} className="card-interactive p-4">
                <p className="text-sm text-white/60">{a.type}</p>
                <div className="flex items-baseline gap-2 mt-1"><span className="text-2xl font-bold text-white">{a.managed}</span><span className="text-sm text-white/40">managed</span><span className="text-lg font-bold text-red-400">+{a.shadow}</span><span className="text-sm text-white/40">shadow</span></div>
                <p className="text-xs text-white/40 mt-1">Est. cost: {a.cost}/mo</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "assets" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Name</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Provider</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Dept</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Cost/mo</th></tr></thead>
            <tbody>
              {[
                { name: "Unregistered GPT-4 client", type: "LLM API", provider: "OpenAI", status: "shadow", dept: "Marketing", risk: 82, cost: "$3,200" },
                { name: "Rogue MCP file-server", type: "MCP Server", provider: "Internal", status: "rogue", dept: "Unknown", risk: 94, cost: "$0" },
                { name: "Local Ollama instance", type: "LLM API", provider: "Local", status: "unmanaged", dept: "Engineering", risk: 65, cost: "$0" },
                { name: "Pinecone RAG pipeline", type: "RAG Pipeline", provider: "Pinecone", status: "shadow", dept: "Data", risk: 71, cost: "$1,800" },
                { name: "Claude API (approved)", type: "LLM API", provider: "Anthropic", status: "managed", dept: "Product", risk: 15, cost: "$4,100" },
              ].map((a, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-white/90 font-medium">{a.name}</td>
                  <td className="px-4 py-3 text-white/70">{a.type}</td>
                  <td className="px-4 py-3 text-white/70">{a.provider}</td>
                  <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                  <td className="px-4 py-3 text-white/60">{a.dept}</td>
                  <td className="px-4 py-3"><span className={clsx("font-bold", a.risk > 75 ? "text-red-400" : a.risk > 50 ? "text-yellow-400" : "text-emerald-400")}>{a.risk}%</span></td>
                  <td className="px-4 py-3 text-white/70">{a.cost}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "traffic" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">AI Traffic Patterns (24h)</h3>
          <div className="grid grid-cols-2 gap-4">
            {[{ dest: "api.openai.com", reqs: "12,400", payload: "2.1 GB", managed: false }, { dest: "api.anthropic.com", reqs: "8,900", payload: "1.4 GB", managed: true }, { dest: "internal-mcp:8080", reqs: "3,200", payload: "450 MB", managed: false }, { dest: "pinecone.io", reqs: "5,600", payload: "800 MB", managed: false }].map((t) => (
              <div key={t.dest} className="card-interactive p-4 flex items-center justify-between">
                <div><p className="text-white/90 font-medium font-mono text-sm">{t.dest}</p><p className="text-xs text-white/50">{t.reqs} requests | {t.payload}</p></div>
                <StatusBadge status={t.managed ? "managed" : "unmanaged"} />
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "governance" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Governance Recommendations</h3>
          {[
            { action: "Block", target: "Rogue MCP file-server", reason: "Unidentified owner, no TLS, file system access", priority: "critical" },
            { action: "Onboard", target: "Unregistered GPT-4 client", reason: "Marketing team — route through ShieldOps proxy", priority: "high" },
            { action: "Review", target: "Local Ollama instance", reason: "Engineering use — assess data sensitivity", priority: "medium" },
            { action: "Onboard", target: "Pinecone RAG pipeline", reason: "Data team — add to managed RAG inventory", priority: "medium" },
          ].map((r, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{r.action}: {r.target}</p><p className="text-xs text-white/50">{r.reason}</p></div>
              <StatusBadge status={r.priority} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
