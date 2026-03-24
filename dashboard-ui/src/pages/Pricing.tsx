import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Check, X, ChevronDown, Calculator } from "lucide-react";
import clsx from "clsx";
import { TIERS, COMPARISON, FAQ } from "../config/pricing";

export default function Pricing() {
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [callVolume, setCallVolume] = useState(50_000);

  const estimatedCost = useMemo(() => {
    const base = 499;
    const perCall = 0.005;
    return base + callVolume * perCall;
  }, [callVolume]);

  return (
    <div className="bg-surface-0 pt-24">
      {/* ─── PageHeader ─── */}
      <section className="px-6 pb-4 pt-12 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-gray-50 sm:text-5xl">
          Simple, usage-based pricing
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-lg text-gray-400">
          Start free. Pay only for what you use as you scale AI agent security
          across your organization.
        </p>
      </section>

      {/* ─── Tier Cards ─── */}
      <section className="px-6 py-12">
        <div className="mx-auto grid max-w-6xl gap-6 md:grid-cols-3">
          {TIERS.map((tier) => (
            <div
              key={tier.name}
              className={clsx(
                "hover-lift flex h-full flex-col rounded-2xl border p-6 transition-all duration-200",
                tier.highlighted
                  ? "border-brand-500/40 bg-surface-2 shadow-glow-brand"
                  : "card-surface border-white/[0.06] bg-surface-2",
              )}
            >
              {tier.highlighted && (
                <div className="mb-4 inline-flex self-start rounded-full bg-brand-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-brand-400 ring-1 ring-inset ring-brand-500/20">
                  Most Popular
                </div>
              )}

              <h3 className="text-lg font-semibold text-gray-50">{tier.name}</h3>
              <p className="mt-1 text-sm text-gray-500">{tier.description}</p>

              <div className="mt-5">
                <span className="text-3xl font-bold text-gray-50">{tier.price}</span>
                {tier.usageLine && (
                  <span className="ml-1 text-sm text-gray-500">{tier.usageLine}</span>
                )}
              </div>

              <ul className="mt-6 flex-1 space-y-3">
                {tier.features.map((feature) => (
                  <li
                    key={feature}
                    className="flex items-start gap-2 text-sm text-gray-300"
                  >
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                    {feature}
                  </li>
                ))}
              </ul>

              <div className="mt-6">
                {tier.ctaHref.startsWith("mailto:") ? (
                  <a
                    href={tier.ctaHref}
                    className="block rounded-lg border border-white/[0.06] px-4 py-2.5 text-center text-sm font-medium text-gray-300 transition-all hover:border-gray-500 hover:bg-gray-800/50 hover:text-white"
                  >
                    {tier.cta}
                  </a>
                ) : (
                  <Link
                    to={tier.ctaHref}
                    className={clsx(
                      "btn-primary block rounded-lg px-4 py-2.5 text-center text-sm font-medium transition-all",
                      tier.highlighted
                        ? "bg-brand-600 text-white hover:bg-brand-500 shadow-glow-brand"
                        : "border border-white/[0.06] bg-transparent text-gray-300 hover:border-gray-500 hover:bg-gray-800/40 hover:text-white",
                    )}
                  >
                    {tier.cta}
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Usage Calculator (Pro) ─── */}
      <section className="px-6 py-12">
        <div className="mx-auto max-w-2xl rounded-2xl border border-white/[0.06] bg-surface-2 p-6 sm:p-8">
          <div className="flex items-center gap-3">
            <Calculator className="h-5 w-5 text-brand-400" />
            <h2 className="text-lg font-semibold text-gray-50">
              Pro Plan Usage Calculator
            </h2>
          </div>
          <p className="mt-2 text-sm text-gray-400">
            Estimate your monthly cost based on intercepted call volume.
          </p>

          <div className="mt-6 space-y-4">
            <div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-300">Intercepted calls / month</span>
                <span className="font-mono text-gray-100">
                  {callVolume.toLocaleString()}
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={500_000}
                step={5_000}
                value={callVolume}
                onChange={(e) => setCallVolume(Number(e.target.value))}
                className="mt-2 w-full accent-brand-500"
              />
              <div className="mt-1 flex justify-between text-xs text-gray-600">
                <span>0</span>
                <span>250k</span>
                <span>500k</span>
              </div>
            </div>

            <div className="flex items-baseline justify-between rounded-xl border border-white/[0.06] bg-surface-0 px-4 py-3">
              <span className="text-sm text-gray-400">Estimated monthly cost</span>
              <span className="text-2xl font-bold text-gray-50">
                ${estimatedCost.toLocaleString(undefined, { maximumFractionDigits: 0 })}
              </span>
            </div>

            <p className="text-xs text-gray-500">
              $499 base + {callVolume.toLocaleString()} calls x $0.005/call ={" "}
              ${(callVolume * 0.005).toLocaleString(undefined, { maximumFractionDigits: 0 })} usage
            </p>
          </div>
        </div>
      </section>

      {/* ─── Feature Comparison Table ─── */}
      <section className="px-6 py-12">
        <div className="mx-auto max-w-5xl">
          <h2 className="mb-8 text-center text-2xl font-bold text-gray-50">
            Feature comparison
          </h2>

          <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06] bg-surface-2">
                  <th className="px-4 py-3 text-left font-medium text-gray-400">
                    Feature
                  </th>
                  <th className="px-4 py-3 text-center font-medium text-gray-400">
                    Starter
                  </th>
                  <th className="px-4 py-3 text-center font-medium text-brand-400">
                    Pro
                  </th>
                  <th className="px-4 py-3 text-center font-medium text-gray-400">
                    Enterprise
                  </th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON.map((row, i) => (
                  <tr
                    key={row.feature}
                    className={clsx(
                      "border-b border-white/[0.04]",
                      i % 2 === 0 ? "bg-surface-0" : "bg-surface-2/50",
                    )}
                  >
                    <td className="px-4 py-3 text-gray-300">{row.feature}</td>
                    {(["starter", "pro", "enterprise"] as const).map((tier) => {
                      const val = row[tier];
                      return (
                        <td key={tier} className="px-4 py-3 text-center">
                          {val === true ? (
                            <Check className="mx-auto h-4 w-4 text-emerald-500" />
                          ) : val === false ? (
                            <X className="mx-auto h-4 w-4 text-gray-600" />
                          ) : (
                            <span className="text-gray-300">{val}</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* ─── FAQ Accordion ─── */}
      <section className="px-6 py-16">
        <div className="mx-auto max-w-3xl">
          <h2 className="mb-8 text-center text-2xl font-bold text-gray-50">
            Frequently asked questions
          </h2>

          <div className="space-y-3">
            {FAQ.map((item, i) => (
              <button
                key={i}
                onClick={() => setOpenFaq(openFaq === i ? null : i)}
                className="w-full rounded-xl border border-white/[0.06] bg-surface-2 px-6 py-4 text-left transition-all duration-150 hover:border-gray-700"
                aria-expanded={openFaq === i}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-200">
                    {item.question}
                  </span>
                  <ChevronDown
                    className={clsx(
                      "h-4 w-4 shrink-0 text-gray-500 transition-transform",
                      openFaq === i && "rotate-180",
                    )}
                  />
                </div>
                {openFaq === i && (
                  <p className="mt-3 text-sm leading-relaxed text-gray-400">
                    {item.answer}
                  </p>
                )}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* ─── Bottom CTA ─── */}
      <section className="px-6 py-16">
        <div className="mx-auto max-w-2xl rounded-2xl border border-white/[0.06] bg-surface-2 p-8 text-center sm:p-12">
          <h2 className="text-2xl font-bold text-gray-50">
            Not sure which plan is right?
          </h2>
          <p className="mt-3 text-gray-400">
            Try the live demo or talk to our team for a personalized
            recommendation.
          </p>
          <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Link
              to="/app?demo=true"
              className="btn-primary rounded-lg bg-brand-600 px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-brand-500"
            >
              Try Live Demo
            </Link>
            <a
              href="mailto:founders@shieldops.io"
              className="rounded-lg border border-white/[0.06] px-6 py-3 text-sm font-medium text-gray-300 transition-all hover:border-gray-500 hover:bg-gray-800/50 hover:text-white"
            >
              Talk to Sales
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}
