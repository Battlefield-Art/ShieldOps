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
      { name: "OPA", description: "Policy evaluation on all agent actions" },
    ],
  },
];

export default function IntegrationsSection() {
  return (
    <section id="integrations" className="border-y border-gray-800 bg-gray-900 px-6 py-20">
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
                    className="cursor-default rounded-md border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm font-medium text-gray-300 transition-colors hover:border-cyan-700 hover:text-white"
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
