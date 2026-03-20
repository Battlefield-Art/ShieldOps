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
    <section className="px-6 pb-24 pt-28 sm:pt-32">
      <div className="mx-auto max-w-3xl text-center">
        {/* Private Beta badge */}
        <div className="mb-6 inline-flex items-center gap-2 rounded-md border border-gray-800 bg-gray-900 px-3 py-1 text-xs font-medium text-gray-400">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
          Private Beta
        </div>

        {/* Heading */}
        <h1 className="text-4xl font-bold leading-[1.15] tracking-tight text-gray-50 sm:text-5xl lg:text-[3.5rem]">
          What should we investigate?
        </h1>

        {/* Subheading */}
        <p className="mx-auto mt-5 max-w-2xl text-lg leading-relaxed text-gray-400">
          ShieldOps deploys autonomous AI agents that investigate incidents, remediate
          infrastructure issues, and learn from outcomes — in minutes, not hours.
        </p>

        {/* Chat input container */}
        <div
          className={clsx(
            "mt-10 rounded-xl border border-gray-800 bg-gray-900 transition-all duration-200",
            "focus-within:border-cyan-700/50 focus-within:shadow-[0_0_15px_rgba(8,145,178,0.1)]",
          )}
        >
          <textarea
            rows={3}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Describe an incident, ask a question, or paste an alert..."
            className="w-full resize-none bg-transparent px-4 pt-4 pb-2 text-sm text-gray-200 placeholder-gray-500 outline-none"
          />
          <div className="flex items-center justify-between border-t border-gray-800 px-3 py-2">
            <button
              type="button"
              className="rounded-lg p-2 text-gray-500 transition-colors hover:bg-gray-800 hover:text-gray-300"
              aria-label="Attach file"
            >
              <Paperclip className="h-4 w-4" />
            </button>
            <Link
              to="/app?demo=true"
              className={clsx(
                "inline-flex items-center gap-2 rounded-lg bg-cyan-700 px-4 py-1.5 text-sm font-medium text-white transition-all hover:bg-cyan-600",
                input.length > 0 && "shadow-[0_0_12px_rgba(8,145,178,0.25)]",
              )}
            >
              Send to Agent
              <ArrowUp className="h-4 w-4" />
            </Link>
          </div>
        </div>

        {/* Example prompt chips */}
        <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
          {examplePrompts.map((prompt) => (
            <button
              key={prompt.label}
              type="button"
              onClick={() => setInput(prompt.label)}
              className={clsx(
                "inline-flex items-center gap-1.5 rounded-full border border-gray-800 bg-gray-900 px-4 py-2 text-sm text-gray-400",
                "transition-all hover:border-gray-600 hover:text-gray-200 active:scale-[0.97]",
              )}
            >
              <prompt.icon className="h-3.5 w-3.5" />
              {prompt.label}
            </button>
          ))}
        </div>

        {/* Trust signals */}
        <p className="mt-8 text-xs text-gray-500">
          No signup required &middot; 50 autonomous agents &middot; SOC 2 compliant
        </p>
      </div>
    </section>
  );
}
