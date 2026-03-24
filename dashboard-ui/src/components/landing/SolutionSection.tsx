import { Shield, Plug, KeyRound } from "lucide-react";

const LAYERS = [
  {
    icon: Shield,
    title: "Orchestration Layer",
    subtitle: "Agent Behavioral Firewall",
    description:
      "Every AI agent tool call is intercepted at runtime. Behavioral baselines detect anomalies, circuit breakers halt rogue agents, and kill switches provide instant containment.",
    capabilities: [
      "Runtime interception of all tool calls and API requests",
      "Behavioral baselines with anomaly scoring per agent",
      "Circuit breakers and one-click kill switch",
      "Prompt injection and jailbreak detection",
    ],
  },
  {
    icon: Plug,
    title: "Tool / Action Layer",
    subtitle: "MCP Security Gateway",
    description:
      "Secure every MCP server connection with zero-trust enforcement. Detect God Keys, scan supply chains, and enforce least-privilege across your entire MCP ecosystem.",
    capabilities: [
      "God Key detection — flag over-privileged server credentials",
      "MCP supply chain scanning and integrity verification",
      "Zero-trust enforcement for every server connection",
      "Permission auditing with automated remediation suggestions",
    ],
  },
  {
    icon: KeyRound,
    title: "Data / Identity Layer",
    subtitle: "NHI Registry + JIT Credentials",
    description:
      "Discover and govern every non-human identity across your cloud. Shadow AI detection surfaces unregistered agents, and JIT credentials eliminate standing privileges.",
    capabilities: [
      "Shadow AI discovery across all cloud accounts",
      "Non-human identity inventory with posture scoring",
      "JIT credential issuance with configurable TTL",
      "Continuous posture monitoring and drift alerting",
    ],
  },
];

export default function SolutionSection() {
  return (
    <section id="solution" className="bg-surface-0 px-6 py-20">
      <div className="mx-auto max-w-6xl">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-50">
            Three-tier security for AI agents
          </h2>
          <p className="mt-3 text-gray-400">
            Defense in depth — from orchestration to identity. Every layer enforced, every action audited.
          </p>
        </div>
        <div className="mt-12 grid gap-8 lg:grid-cols-3">
          {LAYERS.map((layer) => (
            <div
              key={layer.title}
              className="rounded-lg border border-white/[0.06] bg-surface-1 p-8 transition-colors hover:border-brand-500/30"
            >
              <layer.icon className="h-7 w-7 text-brand-400" />
              <h3 className="mt-4 text-xl font-semibold text-gray-100">
                {layer.title}
              </h3>
              <p className="mt-1 text-sm font-medium text-brand-400">
                {layer.subtitle}
              </p>
              <p className="mt-3 text-sm leading-relaxed text-gray-400">
                {layer.description}
              </p>
              <ul className="mt-5 space-y-2">
                {layer.capabilities.map((item) => (
                  <li
                    key={item}
                    className="flex items-start gap-2 text-sm text-gray-300"
                  >
                    <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-brand-400" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
