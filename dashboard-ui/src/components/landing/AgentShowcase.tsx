import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import clsx from "clsx";

interface ShowcaseCard {
  title: string;
  agent: string;
  status: string;
  statusColor: string;
  accentBorder: string;
  details: string[];
  metrics: string;
}

const SHOWCASE_CARDS: ShowcaseCard[] = [
  {
    title: "Payment service crash — resolved in 4 minutes",
    agent: "Investigation Agent",
    status: "Resolved",
    statusColor: "bg-emerald-900/60 text-emerald-400",
    accentBorder: "border-t-emerald-500/70",
    details: [
      "Correlated 47 OOMKilled events with memory spike",
      "Identified Redis connection pool leak in v2.3.1",
      "Rolled back to v2.3.0, pods recovered",
    ],
    metrics: "MTTR: 4m 12s \u00b7 Confidence: 91%",
  },
  {
    title: "Threat intel scan — 3 IOCs blocked",
    agent: "Threat Intel Agent",
    status: "Completed",
    statusColor: "bg-cyan-900/60 text-cyan-400",
    accentBorder: "border-t-cyan-500/70",
    details: [
      "Collected 142 indicators from OSINT feeds",
      "Correlated against internal logs \u2014 3 matches",
      "Blocked 2 IPs and 1 domain at firewall",
    ],
    metrics: "Sources: 5 feeds \u00b7 Relevance: 0.87",
  },
  {
    title: "Telemetry costs reduced by 34%",
    agent: "Telemetry Optimizer Agent",
    status: "Applied",
    statusColor: "bg-amber-900/60 text-amber-400",
    accentBorder: "border-t-amber-500/70",
    details: [
      "Identified high-cardinality metrics on 3 services",
      "Proposed label reduction and sampling adjustment",
      "Experiment confirmed 34% cost reduction, no SLO impact",
    ],
    metrics: "Savings: $2,400/mo \u00b7 SLO impact: none",
  },
];

export default function AgentShowcase() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-24">
      <div className="mb-12 text-center">
        <h2 className="text-3xl font-semibold tracking-tight text-gray-100 sm:text-4xl">
          See what ShieldOps agents can do
        </h2>
        <p className="mt-3 text-lg text-gray-500">
          Real investigations, real remediations, real results.
        </p>
      </div>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {SHOWCASE_CARDS.map((card) => (
          <Link
            key={card.title}
            to="/app?demo=true"
            className={clsx(
              "group rounded-xl border border-t-2 border-gray-800 bg-gray-900 p-6 transition-all duration-200 hover:-translate-y-0.5 hover:border-gray-700",
              card.accentBorder,
            )}
          >
            <div className="mb-3 flex items-center justify-between">
              <span className="text-xs uppercase tracking-wider text-gray-500">
                {card.agent}
              </span>
              <span
                className={clsx(
                  "relative overflow-hidden rounded-full px-2.5 py-0.5 text-xs font-medium",
                  card.statusColor,
                )}
              >
                {card.status}
                <span
                  className="absolute inset-0 animate-shimmer bg-gradient-to-r from-transparent via-white/[0.06] to-transparent bg-[length:200%_100%]"
                  aria-hidden="true"
                />
              </span>
            </div>

            <h3 className="text-lg font-semibold text-gray-100">{card.title}</h3>

            <ul className="mt-4 space-y-2">
              {card.details.map((detail, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-400">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-gray-600" />
                  {detail}
                </li>
              ))}
            </ul>

            <div className="mt-4 flex items-center justify-between border-t border-gray-800 pt-3">
              <span className="text-xs text-gray-500">{card.metrics}</span>
              <ArrowRight className="h-4 w-4 text-gray-600 transition-all duration-200 group-hover:translate-x-1 group-hover:-translate-y-0.5 group-hover:text-gray-400" />
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}
