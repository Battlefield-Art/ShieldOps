import { Link } from "react-router-dom";
import { Play, ArrowRight } from "lucide-react";

export default function CTASection() {
  return (
    <section className="bg-gray-950 px-6 py-24">
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="text-3xl font-bold text-gray-50">
          See ShieldOps in action
        </h2>
        <p className="mt-4 text-gray-400">
          Start with a live demo using sample data, or book a walkthrough with
          our team to see it on your infrastructure.
        </p>
        <div className="mt-8 flex flex-col items-center justify-center gap-4 sm:flex-row">
          <Link
            to="/app?demo=true"
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-cyan-500"
          >
            <Play className="h-4 w-4" />
            Try Live Demo
          </Link>
          <a
            href="mailto:founders@shieldops.io"
            className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-6 py-3 text-sm font-semibold text-gray-300 transition-colors hover:border-gray-500 hover:text-white"
          >
            Book a Walkthrough
            <ArrowRight className="h-4 w-4" />
          </a>
        </div>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs text-gray-500">
          <span>No signup required</span>
          <span className="hidden sm:inline text-gray-700">|</span>
          <span>SOC 2 Type II</span>
          <span className="hidden sm:inline text-gray-700">|</span>
          <span>Deploys in under 10 minutes</span>
        </div>
      </div>
    </section>
  );
}
