import { useState } from "react";
import { Blocks, Code, CheckCircle, Rocket, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "create" | "agents" | "templates";
const TABS: { id: TabId; label: string }[] = [{ id: "create", label: "Create Agent" }, { id: "agents", label: "Custom Agents" }, { id: "templates", label: "Templates" }];
export default function CustomAgentFactory() {
  const [tab, setTab] = useState<TabId>("create");
  return (<div className="space-y-6">
    <PageHeader title="Custom Agent Factory" subtitle="Generate custom security agents from natural language" icon={<Blocks className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Agents Created" value="8" icon={<Blocks className="h-5 w-5" />} />
      <MetricCard title="Deployed" value="6" icon={<Rocket className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Code Quality" value="94%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Avg Build Time" value="2.1 min" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "create" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Describe Your Agent</h3>
      <textarea className="w-full bg-white/5 border border-white/10 rounded-lg p-4 text-sm text-white/90 placeholder-white/30 h-32" placeholder="Describe what your custom agent should do. Example: 'Monitor our Kubernetes clusters for pods running as root, flag any that don't have security contexts set, and auto-apply a restricted security policy...'" />
      <div className="flex gap-3"><button className="btn-primary px-4 py-2 flex items-center gap-2"><Code className="h-4 w-4" /> Generate Agent</button><button className="btn-secondary px-4 py-2">Preview Design</button></div>
      <p className="text-xs text-white/40">The factory generates a complete LangGraph agent with models, tools, nodes, graph, runner, and tests. All code is version-controlled and testable.</p></div>)}
    {tab === "agents" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Agent</th><th className="px-4 py-3">Category</th><th className="px-4 py-3">Quality</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "k8s-root-pod-monitor", cat: "monitoring", quality: "96%", status: "deployed" },
        { name: "aws-cost-anomaly-detector", cat: "monitoring", quality: "94%", status: "deployed" },
        { name: "github-secret-scanner", cat: "detection", quality: "92%", status: "deployed" },
        { name: "slack-incident-notifier", cat: "response", quality: "98%", status: "deployed" },
        { name: "pci-evidence-collector", cat: "compliance", quality: "91%", status: "testing" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{a.name}</td><td className="px-4 py-3"><StatusBadge status={a.cat} /></td><td className="px-4 py-3 text-emerald-400">{a.quality}</td><td className="px-4 py-3"><StatusBadge status={a.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "templates" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Agent Templates</h3>
      {[{ name: "Detection Agent", desc: "Monitor for specific events and alert", nodes: 5, status: "available" },
        { name: "Response Agent", desc: "Auto-respond to specific incident types", nodes: 6, status: "available" },
        { name: "Compliance Agent", desc: "Collect evidence for a specific framework", nodes: 5, status: "available" },
        { name: "Monitoring Agent", desc: "Continuously monitor a specific resource", nodes: 4, status: "available" },
        { name: "Testing Agent", desc: "Test specific security controls", nodes: 6, status: "available" },
      ].map((t, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{t.name}</p><p className="text-xs text-white/50">{t.desc} | {t.nodes} nodes</p></div><StatusBadge status={t.status} /></div>))}</div>)}
  </div>);
}
