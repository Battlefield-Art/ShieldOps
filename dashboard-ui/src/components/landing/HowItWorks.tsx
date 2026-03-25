import { Bell, Search, Target, ShieldCheck, CheckCircle } from "lucide-react";

const STEPS = [
  { icon: Bell, label: "Alert Fires", description: "PagerDuty, Prometheus, CloudWatch" },
  { icon: Search, label: "AI Investigates", description: "Logs, metrics, traces correlated" },
  { icon: Target, label: "Root Cause Found", description: "91% confidence in minutes" },
  { icon: ShieldCheck, label: "Policy Check", description: "OPA validates remediation" },
  { icon: CheckCircle, label: "Auto-Resolve", description: "Rollback, scale, or patch" },
];

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="border-y border-white/[0.06] bg-surface-2 px-6 py-20">
      <div className="mx-auto max-w-6xl">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-50">How it works</h2>
          <p className="mt-3 text-gray-400">
            From alert to resolution in minutes, not hours.
          </p>
        </div>

        {/* Horizontal step flow */}
        <div className="mt-14 hidden lg:block">
          <div className="flex items-start justify-between">
            {STEPS.map((step, idx) => (
              <div key={step.label} className="flex items-start">
                <div className="flex flex-col items-center text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full border-2 border-cyan-700 bg-surface-0">
                    <span className="text-sm font-bold text-cyan-400">{idx + 1}</span>
                  </div>
                  <step.icon className="mt-3 h-5 w-5 text-gray-400" />
                  <h3 className="mt-2 text-sm font-semibold text-gray-100">
                    {step.label}
                  </h3>
                  <p className="mt-1 w-36 text-xs text-gray-500">
                    {step.description}
                  </p>
                </div>
                {idx < STEPS.length - 1 && (
                  <div className="mt-6 w-16 flex-shrink-0 border-t border-dashed border-white/[0.1] xl:w-24" />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Mobile: vertical layout */}
        <div className="mt-12 space-y-6 lg:hidden">
          {STEPS.map((step, idx) => (
            <div key={step.label} className="flex items-start gap-4">
              <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full border-2 border-cyan-700 bg-surface-0">
                <span className="text-sm font-bold text-cyan-400">{idx + 1}</span>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-gray-100">{step.label}</h3>
                <p className="mt-1 text-xs text-gray-500">{step.description}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Terminal mockup */}
        <div className="mx-auto mt-16 max-w-2xl overflow-hidden rounded-lg border border-white/[0.1] bg-surface-0">
          {/* Terminal chrome */}
          <div className="flex items-center gap-2 border-b border-white/[0.06] bg-surface-2 px-4 py-2.5">
            <span className="h-3 w-3 rounded-full bg-red-500/80" />
            <span className="h-3 w-3 rounded-full bg-yellow-500/80" />
            <span className="h-3 w-3 rounded-full bg-green-500/80" />
            <span className="ml-3 text-xs text-gray-500">investigation-agent.log</span>
          </div>
          <pre className="overflow-x-auto p-5 font-mono text-xs leading-relaxed">
            <code>
              <span className="text-cyan-400">[14:23:01]</span>
              <span className="text-gray-300"> Alert received: </span>
              <span className="text-yellow-300">KubePodCrashLooping</span>
              <span className="text-gray-400"> on payment-service</span>
              {"\n"}
              <span className="text-cyan-400">[14:23:04]</span>
              <span className="text-gray-300"> Analyzing pod logs... </span>
              <span className="text-gray-400">found 47 OOMKilled events</span>
              {"\n"}
              <span className="text-cyan-400">[14:23:08]</span>
              <span className="text-gray-300"> Correlating metrics: </span>
              <span className="text-gray-400">memory usage 2.1Gi (limit: 1.5Gi)</span>
              {"\n"}
              <span className="text-cyan-400">[14:23:12]</span>
              <span className="text-gray-300"> Checking recent deployments: </span>
              <span className="text-gray-400">v2.3.1 deployed 2h ago</span>
              {"\n"}
              <span className="text-cyan-400">[14:23:15]</span>
              <span className="text-white font-medium"> Root cause: </span>
              <span className="text-red-400">Redis connection pool leak in v2.3.1</span>
              {"\n"}
              <span className="text-cyan-400">[14:23:15]</span>
              <span className="text-gray-300"> Confidence: </span>
              <span className="text-green-400">91%</span>
              <span className="text-gray-400"> | Recommended: rollback to v2.3.0</span>
              {"\n"}
              <span className="text-cyan-400">[14:23:18]</span>
              <span className="text-gray-300"> OPA policy check: </span>
              <span className="text-green-400">PASS</span>
              <span className="text-gray-400"> (rollback_deployment allowed)</span>
              {"\n"}
              <span className="text-cyan-400">[14:23:20]</span>
              <span className="text-yellow-300"> Awaiting approval </span>
              <span className="text-gray-400">for production rollback...</span>
            </code>
          </pre>
        </div>
      </div>
    </section>
  );
}
