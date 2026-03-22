import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUp, Paperclip, Search, Shield, Activity, GitBranch, BarChart3 } from "lucide-react";
import clsx from "clsx";

const examplePrompts = [
  { label: "Investigate CPU spike on prod", icon: Search },
  { label: "Optimize telemetry costs", icon: BarChart3 },
  { label: "Run threat intelligence scan", icon: Shield },
  { label: "Detect infrastructure drift", icon: GitBranch },
  { label: "Analyze SLO burn rate", icon: Activity },
];

export default function HeroSection() {
  const [input, setInput] = useState("");

  return (
    <section className="relative px-6 pb-24 pt-28 sm:pt-36">
      {/* Subtle radial gradient */}
      <div className="absolute inset-0 bg-hero-mesh pointer-events-none" />

      <div className="relative mx-auto max-w-3xl text-center">
        {/* Private Beta badge */}
        <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-white/[0.06] bg-white/[0.03] px-3.5 py-1.5 text-xs font-medium text-gray-400">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand-400 opacity-60" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-brand-400" />
          </span>
          Private Beta
        </div>

        {/* Heading */}
        <h1 className="text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl lg:text-[3.5rem]">
          <span className="text-gradient-white">What should we</span>
          <br />
          <span className="text-gradient-brand">investigate?</span>
        </h1>

        {/* Subheading */}
        <p className="mx-auto mt-6 max-w-xl text-[15px] leading-relaxed text-gray-500">
          ShieldOps deploys autonomous AI agents that investigate incidents,
          remediate infrastructure issues, and learn from outcomes — in minutes, not hours.
        </p>

        {/* Chat input container */}
        <div
          className={clsx(
            "mt-10 rounded-2xl border transition-all duration-250",
            "border-white/[0.06] bg-surface-2",
            "focus-within:border-brand-500/30 focus-within:shadow-glow-brand",
          )}
          style={{
            boxShadow: "0 0 0 1px rgba(255,255,255,0.02), 0 4px 24px rgba(0,0,0,0.4)",
          }}
        >
          <textarea
            rows={3}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Describe an incident, ask a question, or paste an alert..."
            className="w-full resize-none bg-transparent px-5 pt-5 pb-2 text-sm text-gray-200 placeholder-gray-600 outline-none leading-relaxed"
          />
          <div className="flex items-center justify-between border-t border-white/[0.04] px-4 py-2.5">
            <button
              type="button"
              className="rounded-lg p-2 text-gray-600 transition-colors hover:bg-white/[0.04] hover:text-gray-400"
              aria-label="Attach file"
            >
              <Paperclip className="h-4 w-4" />
            </button>
            <Link
              to="/app?demo=true"
              className={clsx(
                "btn-primary rounded-xl px-5 py-2",
                input.length > 0 && "shadow-glow-brand",
              )}
            >
              Send to Agent
              <ArrowUp className="h-4 w-4" />
            </Link>
          </div>
        </div>

        {/* Example prompt chips */}
        <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
          {examplePrompts.map((prompt) => (
            <button
              key={prompt.label}
              type="button"
              onClick={() => setInput(prompt.label)}
              className={clsx(
                "inline-flex items-center gap-1.5 rounded-full border px-4 py-2 text-[13px]",
                "border-white/[0.06] bg-white/[0.02] text-gray-500",
                "transition-all duration-200 hover:border-white/[0.1] hover:text-gray-300 active:scale-[0.97]",
              )}
            >
              <prompt.icon className="h-3.5 w-3.5" />
              {prompt.label}
            </button>
          ))}
        </div>

        {/* Trust signals */}
        <p className="mt-10 text-[11px] tracking-wide text-gray-700">
          No signup required &middot; 50 autonomous agents &middot; SOC 2 compliant
        </p>
      </div>
    </section>
  );
}
