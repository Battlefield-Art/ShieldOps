export interface PricingTier {
  name: string;
  price: string; // display string e.g. "Free", "$499/mo + usage", "Custom"
  description: string;
  features: string[];
  highlighted?: boolean;
  cta: string;
  ctaHref: string;
  usageLine?: string; // optional usage detail shown under price
}

export const TIERS: PricingTier[] = [
  {
    name: "Starter",
    price: "Free",
    description: "Get started with basic AI security monitoring at no cost.",
    features: [
      "1 AI app monitored",
      "Audit mode only (observe, no enforce)",
      "1,000 intercepted calls/mo",
      "Basic NHI scanning",
      "Community support",
    ],
    cta: "Start free",
    ctaHref: "/app?demo=true",
  },
  {
    name: "Pro",
    price: "$499",
    usageLine: "/mo + usage",
    description: "Full enforcement, unlimited apps, and deep visibility into your AI stack.",
    features: [
      "Unlimited AI apps monitored",
      "Enforce mode (block + rewrite)",
      "$0.005 per intercepted call",
      "Full NHI registry + shadow AI detection",
      "MCP scanning (5 servers)",
      "10 SOC Brain situations/mo",
      "Email support",
    ],
    highlighted: true,
    cta: "Start trial",
    ctaHref: "/app?demo=true",
  },
  {
    name: "Enterprise",
    price: "Custom",
    description: "Everything in Pro plus advanced integrations, unlimited scale, and dedicated support.",
    features: [
      "Everything in Pro",
      "SOC Brain (unlimited situations)",
      "Unlimited MCP servers",
      "CrowdStrike, Defender & Wiz connectors",
      "JIT credentials & ephemeral tokens",
      "Custom SLAs",
      "HITL approval workflows",
      "Dedicated CSM",
    ],
    cta: "Contact sales",
    ctaHref: "mailto:founders@shieldops.io",
  },
];

export interface FeatureRow {
  feature: string;
  starter: boolean | string;
  pro: boolean | string;
  enterprise: boolean | string;
}

export const COMPARISON: FeatureRow[] = [
  { feature: "AI apps monitored", starter: "1", pro: "Unlimited", enterprise: "Unlimited" },
  { feature: "Intercepted calls", starter: "1,000/mo", pro: "Pay per call", enterprise: "Volume pricing" },
  { feature: "Enforcement mode", starter: false, pro: true, enterprise: true },
  { feature: "NHI registry", starter: "Basic scan", pro: "Full registry", enterprise: "Full registry" },
  { feature: "Shadow AI detection", starter: false, pro: true, enterprise: true },
  { feature: "MCP server scanning", starter: false, pro: "5 servers", enterprise: "Unlimited" },
  { feature: "SOC Brain situations", starter: false, pro: "10/mo", enterprise: "Unlimited" },
  { feature: "CrowdStrike connector", starter: false, pro: false, enterprise: true },
  { feature: "Defender connector", starter: false, pro: false, enterprise: true },
  { feature: "Wiz connector", starter: false, pro: false, enterprise: true },
  { feature: "JIT credentials", starter: false, pro: false, enterprise: true },
  { feature: "HITL approval workflows", starter: false, pro: false, enterprise: true },
  { feature: "Custom SLAs", starter: false, pro: false, enterprise: true },
  { feature: "Dedicated CSM", starter: false, pro: false, enterprise: true },
  { feature: "Support", starter: "Community", pro: "Email", enterprise: "Dedicated" },
];

export const FAQ = [
  {
    question: "How does usage-based pricing work on the Pro plan?",
    answer:
      "You pay a flat $499/mo base fee plus $0.005 for every intercepted AI agent call beyond the included allowance. The usage calculator on this page lets you estimate your monthly cost based on expected call volume.",
  },
  {
    question: "What counts as an intercepted call?",
    answer:
      "Every tool call, API request, or function invocation made by an AI agent that passes through the ShieldOps Agent Firewall counts as one intercepted call. Duplicate retries within a 5-second window are de-duplicated.",
  },
  {
    question: "Can I start with Starter and upgrade later?",
    answer:
      "Absolutely. Your Starter account preserves all audit history and configuration. Upgrading to Pro or Enterprise is seamless with zero downtime.",
  },
  {
    question: "What is the difference between audit mode and enforce mode?",
    answer:
      "Audit mode logs every agent action for visibility but never blocks execution. Enforce mode actively evaluates policies and can block, rewrite, or escalate calls that violate your security rules.",
  },
  {
    question: "Do you offer annual billing?",
    answer:
      "Yes. Annual commitments on Pro and Enterprise receive a 20% discount on the base fee. Usage charges remain pay-as-you-go regardless of billing cycle.",
  },
  {
    question: "How do I get started with the Enterprise plan?",
    answer:
      "Contact our sales team at founders@shieldops.io. We will schedule a discovery call, run a proof-of-value in your environment, and build a custom pricing package based on your scale and compliance needs.",
  },
];
