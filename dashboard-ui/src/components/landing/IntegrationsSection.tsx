interface Integration {
  name: string;
  description: string;
}

interface Category {
  title: string;
  integrations: Integration[];
}

const CATEGORIES: Category[] = [
  {
    title: "Security",
    integrations: [
      { name: "CrowdStrike", description: "EDR telemetry, threat intelligence, and incident response" },
      { name: "Microsoft Defender", description: "XDR alerts, identity protection, and cloud security" },
      { name: "Wiz", description: "Cloud security posture, vulnerability findings, and attack paths" },
      { name: "OPA", description: "Policy evaluation on all agent actions" },
    ],
  },
  {
    title: "AI / Agent SDKs",
    integrations: [
      { name: "LangChain", description: "Agent monitoring, tool call interception, and guardrails" },
      { name: "CrewAI", description: "Multi-agent crew governance and behavioral analysis" },
      { name: "LlamaIndex", description: "RAG pipeline security and data access auditing" },
      { name: "MCP Servers", description: "Model Context Protocol server discovery and security" },
    ],
  },
  {
    title: "Cloud",
    integrations: [
      { name: "AWS", description: "EC2, ECS, Lambda, CloudWatch, IAM" },
      { name: "GCP", description: "GKE, Cloud Run, Cloud Monitoring" },
      { name: "Azure", description: "AKS, App Service, Azure Monitor" },
    ],
  },
  {
    title: "Orchestration",
    integrations: [
      { name: "Kubernetes", description: "Pod lifecycle, deployments, HPA" },
      { name: "Terraform", description: "IaC drift detection and reconciliation" },
    ],
  },
  {
    title: "Observability",
    integrations: [
      { name: "OpenTelemetry", description: "Native OTel pipeline management and auto-instrumentation" },
      { name: "Prometheus", description: "Metric ingestion and alerting" },
      { name: "Datadog", description: "APM, logs, and infrastructure metrics" },
      { name: "Splunk", description: "Log analytics and SIEM integration" },
      { name: "Grafana", description: "Dashboard and alert forwarding" },
      { name: "Kafka", description: "Telemetry streaming via OTel Kafka receiver" },
    ],
  },
  {
    title: "Incident Management",
    integrations: [
      { name: "PagerDuty", description: "Alert routing and escalation" },
      { name: "Slack", description: "ChatOps notifications and approvals" },
      { name: "Jira", description: "Ticket creation and tracking" },
    ],
  },
  {
    title: "Infrastructure",
    integrations: [
      { name: "PostgreSQL", description: "Query performance and replication" },
      { name: "Redis", description: "Cache health and memory management" },
      { name: "GitHub Actions", description: "CI/CD pipeline integration" },
    ],
  },
];

export default function IntegrationsSection() {
  return (
    <section id="integrations" className="border-y border-white/[0.06] bg-surface-1 px-6 py-20">
      <div className="mx-auto max-w-5xl">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-50">
            Works with your stack
          </h2>
          <p className="mt-3 text-gray-400">
            Plug into the tools you already use. No rip-and-replace.
          </p>
        </div>
        <div className="mt-12 grid gap-8 sm:grid-cols-2 lg:grid-cols-3">
          {CATEGORIES.map((category) => (
            <div key={category.title}>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                {category.title}
              </h3>
              <div className="mt-3 flex flex-wrap gap-2">
                {category.integrations.map((integration) => (
                  <span
                    key={integration.name}
                    title={integration.description}
                    className="cursor-default rounded-md border border-white/[0.06] bg-surface-2 px-3 py-1.5 text-sm font-medium text-gray-300 transition-colors hover:border-brand-500/30 hover:text-white"
                  >
                    {integration.name}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
