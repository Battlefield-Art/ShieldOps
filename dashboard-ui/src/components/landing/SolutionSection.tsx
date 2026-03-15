import { Search, Wrench, Brain } from "lucide-react";

const CAPABILITIES = [
  {
    icon: Search,
    title: "Investigate",
    description:
      "AI agents correlate logs, metrics, and traces across your entire stack. Root cause identified in minutes, not hours.",
    capabilities: [
      "Cross-stack log, metric, and trace correlation",
      "Automated root cause analysis with confidence scoring",
      "Threat intelligence with IOC correlation and MITRE mapping",
      "Telemetry cost analysis and cardinality control",
    ],
  },
  {
    icon: Wrench,
    title: "Remediate",
    description:
      "Agents execute infrastructure changes with OPA policy gates and human approval for high-risk actions.",
    capabilities: [
      "Automated rollbacks, scaling, and patching",
      "OPA policy evaluation on every action",
      "Pre-remediation snapshots with one-click rollback",
      "Blast-radius limits enforced per environment",
    ],
  },
  {
    icon: Brain,
    title: "Learn",
    description:
      "Every incident makes the system smarter. Agents update playbooks, refine thresholds, and build institutional knowledge.",
    capabilities: [
      "Automatic playbook generation from resolved incidents",
      "Swarm intelligence for multi-agent coordination",
      "Knowledge distillation across the agent fleet",
      "Self-healing analytics with feedback-driven optimization",
    ],
  },
];

export default function SolutionSection() {
  return (
    <section id="solution" className="bg-gray-950 px-6 py-20">
      <div className="mx-auto max-w-6xl">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-50">
            An SRE platform that actually takes action
          </h2>
          <p className="mt-3 text-gray-400">
            Not just monitoring. Not just alerting. Autonomous resolution.
          </p>
        </div>
        <div className="mt-12 grid gap-8 lg:grid-cols-3">
          {CAPABILITIES.map((cap) => (
            <div
              key={cap.title}
              className="rounded-lg border border-gray-800 bg-gray-900 p-8 transition-colors hover:border-cyan-700"
            >
              <cap.icon className="h-7 w-7 text-cyan-400" />
              <h3 className="mt-4 text-xl font-semibold text-gray-100">
                {cap.title}
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-gray-400">
                {cap.description}
              </p>
              <ul className="mt-5 space-y-2">
                {cap.capabilities.map((item) => (
                  <li
                    key={item}
                    className="flex items-start gap-2 text-sm text-gray-300"
                  >
                    <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-cyan-500" />
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
