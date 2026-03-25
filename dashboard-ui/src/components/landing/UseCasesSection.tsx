import { Link } from "react-router-dom";
import {
  ArrowRight,
  Server,
  Shield,
  DollarSign,
  FileCheck,
  Code,
  Store,
  type LucideIcon,
} from "lucide-react";
import clsx from "clsx";

interface UseCase {
  icon: LucideIcon;
  color: string;
  title: string;
  audience: string;
  description: string;
  capabilities: string[];
  link: string;
}

const USE_CASES: UseCase[] = [
  {
    icon: Server,
    color: "text-brand-400",
    title: "Managed SRE",
    audience: "For teams without dedicated SRE",
    description:
      "A virtual SRE team that monitors, investigates, and remediates 24/7.",
    capabilities: [
      "24/7 autonomous incident response",
      "Root cause analysis in minutes",
      "Automated rollback and scaling",
    ],
    link: "/products/sre",
  },
  {
    icon: Shield,
    color: "text-red-400",
    title: "Autonomous SOC",
    audience: "For security operations teams",
    description:
      "AI-first SOC that triages, correlates, hunts, and triggers playbooks.",
    capabilities: [
      "Automated alert triage and correlation",
      "MITRE ATT&CK mapped threat hunting",
      "SOAR playbook orchestration",
    ],
    link: "/products/soc",
  },
  {
    icon: DollarSign,
    color: "text-emerald-400",
    title: "FinOps Intelligence",
    audience: "For cloud cost optimization",
    description:
      "Detect anomalies, optimize reservations, and forecast budgets with ML.",
    capabilities: [
      "Cost anomaly detection across providers",
      "RI and savings plan optimization",
      "Tag governance and waste elimination",
    ],
    link: "/products/finops",
  },
  {
    icon: FileCheck,
    color: "text-amber-400",
    title: "Compliance Automation",
    audience: "For regulated industries",
    description:
      "Continuous SOC 2, PCI-DSS, HIPAA, and GDPR compliance monitoring.",
    capabilities: [
      "Automated evidence collection",
      "Continuous control monitoring",
      "Audit-ready reporting",
    ],
    link: "/products/compliance",
  },
  {
    icon: Code,
    color: "text-sky-400",
    title: "Developer API",
    audience: "For platform teams",
    description:
      "Embed ShieldOps capabilities into your own products via metered APIs.",
    capabilities: [
      "RESTful investigation & remediation APIs",
      "Webhook-driven event processing",
      "Usage-based billing built in",
    ],
    link: "/products/api",
  },
  {
    icon: Store,
    color: "text-orange-400",
    title: "Agent Marketplace",
    audience: "For the ecosystem",
    description:
      "Discover community-built agents, connectors, and industry playbooks.",
    capabilities: [
      "Browse and deploy community agents",
      "Publish and monetize your own",
      "Industry-specific playbook packs",
    ],
    link: "/products/marketplace",
  },
];

export default function UseCasesSection() {
  return (
    <section className="bg-surface-1 px-6 py-24">
      <div className="mx-auto max-w-6xl">
        <div className="mb-4">
          <p className="text-sm font-medium uppercase tracking-wider text-brand-400">
            Use Cases
          </p>
        </div>
        <div className="mb-12 max-w-2xl">
          <h2 className="text-3xl font-bold tracking-tight text-gray-50">
            Built for every ops team
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            From SRE to SOC to FinOps — deploy the right agents for your
            operational challenges.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {USE_CASES.map((uc) => {
            const Icon = uc.icon;
            return (
              <Link
                key={uc.title}
                to={uc.link}
                className="group flex flex-col rounded-xl border border-white/[0.06] bg-surface-0 p-6 transition-colors hover:border-white/[0.1] hover:bg-surface-2"
              >
                <div className="mb-1 flex items-center gap-3">
                  <Icon className={clsx("h-5 w-5 shrink-0", uc.color)} />
                  <h3 className="font-semibold text-gray-100">{uc.title}</h3>
                </div>
                <p className="mb-3 text-xs text-gray-500">{uc.audience}</p>
                <p className="text-sm leading-relaxed text-gray-400">
                  {uc.description}
                </p>
                <ul className="mt-4 flex-1 space-y-1.5">
                  {uc.capabilities.map((cap) => (
                    <li
                      key={cap}
                      className="flex items-start gap-2 text-sm text-gray-500"
                    >
                      <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-gray-600" />
                      {cap}
                    </li>
                  ))}
                </ul>
                <span className="mt-5 inline-flex items-center gap-1 text-sm font-medium text-brand-400 transition-colors group-hover:text-brand-300">
                  Learn more
                  <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                </span>
              </Link>
            );
          })}
        </div>
      </div>
    </section>
  );
}
