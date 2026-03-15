const BENEFITS = [
  {
    metric: "7 min",
    label: "Mean Time to Resolve",
    description: "Down from 45 minutes with manual triage",
  },
  {
    metric: "72%",
    label: "Auto-Resolved",
    description: "Incidents resolved without human intervention",
  },
  {
    metric: "99.95%",
    label: "SLO Compliance",
    description: "Error budgets preserved with proactive remediation",
  },
  {
    metric: "3x",
    label: "Engineering Velocity",
    description: "Less firefighting, more building features",
  },
];

export default function BenefitsSection() {
  return (
    <section id="benefits" className="bg-gray-950 px-6 py-20">
      <div className="mx-auto max-w-6xl">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-50">
            Measurable impact from day one
          </h2>
          <p className="mt-3 text-gray-400">
            Real results from teams running ShieldOps in production.
          </p>
        </div>
        <div className="mt-12 grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {BENEFITS.map((b) => (
            <div key={b.label} className="text-center">
              <p className="text-5xl font-bold tracking-tight text-cyan-400">
                {b.metric}
              </p>
              <h3 className="mt-3 text-base font-semibold text-gray-100">
                {b.label}
              </h3>
              <p className="mt-2 text-sm text-gray-500">{b.description}</p>
            </div>
          ))}
        </div>
        <p className="mt-10 text-center text-xs text-gray-600">
          Based on production deployments
        </p>
      </div>
    </section>
  );
}
