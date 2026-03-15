const STATS = [
  { value: "36", label: "Autonomous Agents" },
  { value: "< 3 min", label: "Avg Response Time" },
  { value: "85%", label: "Incidents Auto-Resolved" },
  { value: "99.95%", label: "Platform Uptime" },
];

export default function SocialProofSection() {
  return (
    <section className="border-y border-gray-800 bg-gray-950 px-6 py-14">
      <div className="mx-auto max-w-5xl">
        <div className="grid grid-cols-2 gap-8 md:grid-cols-4">
          {STATS.map((stat) => (
            <div key={stat.label} className="text-center">
              <p className="text-4xl font-bold tracking-tight text-white">
                {stat.value}
              </p>
              <p className="mt-2 text-sm text-gray-400">{stat.label}</p>
            </div>
          ))}
        </div>

        <p className="mt-10 text-center text-sm text-gray-500">
          Trusted by engineering teams across finance, healthcare, and SaaS
        </p>
      </div>
    </section>
  );
}
