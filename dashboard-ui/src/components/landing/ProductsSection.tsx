import { Link } from "react-router-dom";
import { ArrowRight, Shield, KeyRound, Plug, Brain } from "lucide-react";
import clsx from "clsx";
import { PRODUCTS } from "../../config/products";

interface SecurityProduct {
  id: string;
  name: string;
  tagline: string;
  description: string;
  icon: React.ElementType;
  color: string;
  demoPath: string;
}

const SECURITY_PRODUCTS: SecurityProduct[] = [
  {
    id: "agent-firewall",
    name: "Agent Firewall",
    tagline: "Runtime AI agent interception",
    description:
      "Runtime interception for every AI agent tool call. Behavioral baselines, anomaly detection, circuit breakers, and one-click kill switch.",
    icon: Shield,
    color: "text-red-400",
    demoPath: "/app/agent-firewall?demo=true",
  },
  {
    id: "nhi-registry",
    name: "NHI Registry",
    tagline: "Non-human identity governance",
    description:
      "Discover and govern every non-human identity across your cloud. Shadow AI detection, posture monitoring, JIT credentials.",
    icon: KeyRound,
    color: "text-amber-400",
    demoPath: "/app/nhi-registry?demo=true",
  },
  {
    id: "mcp-security",
    name: "MCP Security",
    tagline: "Secure your MCP ecosystem",
    description:
      "Secure your MCP ecosystem. God Key detection, supply chain scanning, zero-trust enforcement for every server connection.",
    icon: Plug,
    color: "text-cyan-400",
    demoPath: "/app/mcp-security?demo=true",
  },
  {
    id: "soc-brain",
    name: "SOC Brain",
    tagline: "AI-driven security operations",
    description:
      "AI-driven security operations across CrowdStrike, Defender, and Wiz. Outcome-centric situations queue with 1-click response.",
    icon: Brain,
    color: "text-purple-400",
    demoPath: "/app/situations?demo=true",
  },
];

const existingProducts = Object.values(PRODUCTS);

export default function ProductsSection() {
  return (
    <section className="px-6 py-24">
      <div className="mx-auto max-w-5xl">
        <div className="mb-4">
          <p className="text-sm font-medium uppercase tracking-wider text-brand-400">
            Platform
          </p>
        </div>
        <div className="mb-12 max-w-2xl">
          <h2 className="text-3xl font-bold tracking-tight text-gray-50">
            Ten products, one platform
          </h2>
          <p className="mt-4 text-lg leading-relaxed text-gray-400">
            Deploy the modules you need today. Add more as your operations
            mature. Everything shares the same agent infrastructure, data layer,
            and policy engine.
          </p>
        </div>

        <div className="grid gap-px overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.06] sm:grid-cols-2 lg:grid-cols-3">
          {/* Security products first */}
          {SECURITY_PRODUCTS.map((product) => {
            const Icon = product.icon;
            return (
              <Link
                key={product.id}
                to={product.demoPath}
                className="group flex flex-col bg-surface-0 p-6 transition-colors hover:bg-surface-1"
              >
                <div className="flex items-center gap-3">
                  <Icon className={clsx("h-5 w-5 shrink-0", product.color)} />
                  <h3 className="font-semibold text-gray-100">{product.name}</h3>
                </div>
                <p className="mt-1 text-xs text-gray-500">{product.tagline}</p>
                <p className="mt-3 flex-1 text-sm leading-relaxed text-gray-400">
                  {product.description}
                </p>
                <span className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-brand-400 transition-colors group-hover:text-brand-300">
                  Explore
                  <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                </span>
              </Link>
            );
          })}

          {/* Existing products */}
          {existingProducts.map((product) => {
            const Icon = product.icon;
            return (
              <Link
                key={product.id}
                to={`/products/${product.id}`}
                className="group flex flex-col bg-surface-0 p-6 transition-colors hover:bg-surface-1"
              >
                <div className="flex items-center gap-3">
                  <Icon className={clsx("h-5 w-5 shrink-0", product.color)} />
                  <h3 className="font-semibold text-gray-100">{product.name}</h3>
                </div>
                <p className="mt-1 text-xs text-gray-500">{product.tagline}</p>
                <p className="mt-3 flex-1 text-sm leading-relaxed text-gray-400">
                  {product.description}
                </p>
                <span className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-brand-400 transition-colors group-hover:text-brand-300">
                  Explore
                  <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                </span>
              </Link>
            );
          })}
        </div>
      </div>
    </section>
  );
}
