import { Link } from "react-router-dom";
import { Play, ArrowRight } from "lucide-react";

export default function CTASection() {
  return (
    <section className="relative bg-surface-0 px-6 py-24 overflow-hidden">
      {/* Subtle gradient glow */}
      <div className="absolute inset-0 bg-hero-mesh pointer-events-none opacity-50" />

      <div className="relative mx-auto max-w-2xl text-center">
        <h2 className="text-3xl font-bold text-gradient-white">
          See ShieldOps in action
        </h2>
        <p className="mt-4 text-[15px] text-gray-500 leading-relaxed">
          Start with a live demo using sample data, or book a walkthrough with
          our team to see it on your infrastructure.
        </p>
        <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
          <Link
            to="/app?demo=true"
            className="btn-primary rounded-lg px-6 py-3 text-sm font-semibold"
          >
            <Play className="h-4 w-4" />
            Try Live Demo
          </Link>
          <a
            href="mailto:founders@shieldops.io"
            className="btn-secondary rounded-lg px-6 py-3 text-sm font-semibold"
          >
            Book a Walkthrough
            <ArrowRight className="h-4 w-4" />
          </a>
        </div>
        <div className="mt-10 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-[11px] tracking-wide text-gray-700">
          <span>No signup required</span>
          <span className="hidden sm:inline text-gray-800">|</span>
          <span>SOC 2 Type II</span>
          <span className="hidden sm:inline text-gray-800">|</span>
          <span>Deploys in under 10 minutes</span>
        </div>
      </div>
    </section>
  );
}
