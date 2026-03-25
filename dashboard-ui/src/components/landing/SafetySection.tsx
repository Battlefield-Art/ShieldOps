import { ShieldCheck, RotateCcw, UserCheck } from "lucide-react";

const PILLARS = [
  {
    icon: ShieldCheck,
    title: "OPA Policy Gates",
    description:
      "Every agent action is evaluated against Open Policy Agent rules before execution.",
    details: [
      "Blast-radius limits enforced per environment (dev/staging/prod)",
      "Change window restrictions and environment lockdowns",
      "No agent can delete databases, drop tables, or modify IAM root policies",
    ],
  },
  {
    icon: RotateCcw,
    title: "Snapshot Rollback",
    description:
      "Pre-remediation snapshots are taken automatically. One-click rollback if anything goes wrong.",
    details: [
      "Pre-remediation snapshots before every change",
      "Full audit trail for every infrastructure modification",
      "Immutable change log for compliance and forensics",
    ],
  },
  {
    icon: UserCheck,
    title: "Human-in-the-Loop",
    description:
      "High-risk actions require human approval. You decide what runs automatically.",
    details: [
      "Confidence > 0.85: autonomous execution",
      "Confidence 0.5 - 0.85: requires human approval",
      "Confidence < 0.5: escalate to on-call engineer",
    ],
  },
];

export default function SafetySection() {
  return (
    <section id="safety" className="bg-surface-0 px-6 py-20">
      <div className="mx-auto max-w-6xl">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-50">
            Built for security-first enterprises
          </h2>
          <p className="mt-3 text-gray-400">
            Autonomous doesn't mean uncontrolled. Every action is governed.
          </p>
        </div>
        <div className="mt-12 grid gap-8 lg:grid-cols-3">
          {PILLARS.map((pillar) => (
            <div
              key={pillar.title}
              className="rounded-lg border border-white/[0.06] bg-surface-2 p-8 transition-colors hover:border-emerald-800"
            >
              <pillar.icon className="h-7 w-7 text-emerald-400" />
              <h3 className="mt-4 text-lg font-semibold text-gray-100">
                {pillar.title}
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-gray-400">
                {pillar.description}
              </p>
              <ul className="mt-4 space-y-2">
                {pillar.details.map((detail) => (
                  <li
                    key={detail}
                    className="flex items-start gap-2 text-sm text-gray-400"
                  >
                    <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-emerald-500" />
                    {detail}
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
