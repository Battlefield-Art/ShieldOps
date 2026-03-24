import {
  LayoutDashboard,
  Search,
  Wrench,
  BarChart3,
  Gauge,
  TrendingUp,
  HardDrive,
  Brain,
  HeartPulse,
  ShieldAlert,
  Bug,
  Layers,
  BookOpen,
  DollarSign,
  CreditCard,
  ShieldCheck,
  FileText,
  Store,
  Rocket,
  Code,
  Settings,
  Users,
  Sparkles,
  Siren,
  Activity,
  GitBranch,
  Key,
  Workflow,
  CalendarClock,
  Server,
  MessageSquare,
  Plug,
  Zap,
  Target,
  Shield,
  FileCheck,
  Filter,
  Crosshair,
  TestTube2,
  ScrollText,
  type LucideIcon,
} from "lucide-react";

export type ProductId = "sre" | "soc" | "finops" | "compliance" | "platform" | "api" | "marketplace";

export interface Product {
  id: ProductId;
  name: string;
  tagline: string;
  description: string;
  icon: LucideIcon;
  color: string;
  bgGradient: string;
  demoPath: string;
}

export const PRODUCTS: Record<Exclude<ProductId, "platform">, Product> = {
  sre: {
    id: "sre",
    name: "SRE Intelligence",
    tagline: "Autonomous incident response",
    description:
      "50 autonomous agents that investigate alerts, identify root causes, optimize telemetry pipelines, and learn from outcomes — across AWS, GCP, Azure, K8s, and on-prem.",
    icon: LayoutDashboard,
    color: "text-brand-400",
    bgGradient: "from-brand-600/20 to-brand-800/20",
    demoPath: "/app?demo=true",
  },
  soc: {
    id: "soc",
    name: "Security Operations",
    tagline: "AI-powered threat defense",
    description:
      "Autonomous SOC agents for threat intelligence, risk-based alerting, MITRE ATT&CK mapping, vulnerability management, and SOAR playbook orchestration.",
    icon: ShieldAlert,
    color: "text-red-400",
    bgGradient: "from-red-600/20 to-red-800/20",
    demoPath: "/app/security?demo=true",
  },
  finops: {
    id: "finops",
    name: "FinOps Intelligence",
    tagline: "Cloud cost optimization",
    description:
      "Intelligent cost analysis, budget forecasting, and resource optimization across all cloud providers.",
    icon: DollarSign,
    color: "text-emerald-400",
    bgGradient: "from-emerald-600/20 to-emerald-800/20",
    demoPath: "/app/cost?demo=true",
  },
  compliance: {
    id: "compliance",
    name: "Compliance Automation",
    tagline: "Continuous compliance assurance",
    description:
      "Automated compliance monitoring, evidence collection, audit trails, and policy enforcement across your infrastructure.",
    icon: ShieldCheck,
    color: "text-amber-400",
    bgGradient: "from-amber-600/20 to-amber-800/20",
    demoPath: "/app/compliance?demo=true",
  },
  api: {
    id: "api",
    name: "API Platform",
    tagline: "Developer-first agent APIs",
    description:
      "Expose ShieldOps capabilities as metered APIs — investigations, remediations, analytics, and more — for integration into your own tools and portals.",
    icon: Code,
    color: "text-sky-400",
    bgGradient: "from-sky-600/20 to-sky-800/20",
    demoPath: "/app/api-keys?demo=true",
  },
  marketplace: {
    id: "marketplace",
    name: "Agent Marketplace",
    tagline: "Extensible agent ecosystem",
    description:
      "Discover and deploy community-built agents, connectors, and playbooks. Publish your own and earn revenue through the marketplace.",
    icon: Store,
    color: "text-orange-400",
    bgGradient: "from-orange-600/20 to-orange-800/20",
    demoPath: "/app/marketplace?demo=true",
  },
};

export interface NavItem {
  to: string;
  icon: LucideIcon;
  label: string;
}

export interface NavGroup {
  id: string;
  label: string;
  productId?: ProductId;
  color: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "agent-factory",
    label: "Agent Factory",
    color: "text-brand-400",
    items: [
      { to: "/app", icon: Sparkles, label: "Agent Factory" },
      { to: "/app/war-room", icon: Siren, label: "War Rooms" },
      { to: "/app/workflows", icon: Workflow, label: "Workflows" },
      { to: "/app/agent-history", icon: Activity, label: "Agent History" },
      { to: "/app/schedules", icon: CalendarClock, label: "Schedules" },
    ],
  },
  {
    id: "sre",
    label: "SRE Intelligence",
    productId: "sre",
    color: "text-brand-400",
    items: [
      { to: "/app/fleet", icon: LayoutDashboard, label: "Fleet Overview" },
      { to: "/app/investigations", icon: Search, label: "Investigations" },
      { to: "/app/remediations", icon: Wrench, label: "Remediations" },
      { to: "/app/pipeline", icon: GitBranch, label: "Pipeline" },
      { to: "/app/analytics", icon: BarChart3, label: "Analytics" },
      { to: "/app/agent-performance", icon: Gauge, label: "Agent Perf" },
      { to: "/app/predictions", icon: TrendingUp, label: "Predictions" },
      { to: "/app/capacity", icon: HardDrive, label: "Capacity" },
      { to: "/app/learning", icon: Brain, label: "Learning" },
      { to: "/app/system-health", icon: HeartPulse, label: "System Health" },
      { to: "/app/telemetry-optimizer", icon: BarChart3, label: "Telemetry Costs" },
      { to: "/app/incident-commander", icon: Siren, label: "Incident Commander" },
    ],
  },
  {
    id: "security",
    label: "Security Operations",
    productId: "soc",
    color: "text-red-400",
    items: [
      { to: "/app/situations", icon: Target, label: "Situations" },
      { to: "/app/security", icon: ShieldAlert, label: "Security" },
      { to: "/app/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
      { to: "/app/incidents", icon: Layers, label: "Incident Correlation" },
      { to: "/app/playbooks", icon: BookOpen, label: "Playbooks" },
      { to: "/app/risk-scoring", icon: Target, label: "Risk Scoring" },
      { to: "/app/threat-intel", icon: Shield, label: "Threat Intel" },
      { to: "/app/compliance-audit", icon: FileCheck, label: "Compliance Audit" },
      { to: "/app/adaptive-security", icon: ShieldCheck, label: "Adaptive Security" },
      { to: "/app/security-posture", icon: ShieldAlert, label: "Security Posture" },
      { to: "/app/soar-workflow", icon: Zap, label: "SOAR Workflows" },
      { to: "/app/detection-engineering", icon: Crosshair, label: "Detection Eng." },
      { to: "/app/security-testing", icon: TestTube2, label: "Security Testing" },
      { to: "/app/threat-modeling", icon: Shield, label: "Threat Modeling" },
    ],
  },
  {
    id: "finops",
    label: "FinOps Intelligence",
    productId: "finops",
    color: "text-emerald-400",
    items: [
      { to: "/app/cost", icon: DollarSign, label: "Cost" },
      { to: "/app/billing", icon: CreditCard, label: "Billing" },
    ],
  },
  {
    id: "compliance",
    label: "Compliance & Audit",
    productId: "compliance",
    color: "text-amber-400",
    items: [
      { to: "/app/compliance", icon: ShieldCheck, label: "Compliance" },
      { to: "/app/audit-log", icon: FileText, label: "Audit Log" },
    ],
  },
  {
    id: "observability",
    label: "Observability",
    color: "text-cyan-400",
    items: [
      { to: "/app/otel-pipeline", icon: Activity, label: "OTel Pipeline" },
      { to: "/app/otel-collector-manager", icon: Server, label: "Collector Mgmt" },
      { to: "/app/otel-deployer", icon: Rocket, label: "OTel Deployer" },
      { to: "/app/otel-semantic", icon: FileCheck, label: "Semantic Conv." },
      { to: "/app/tail-sampling", icon: Filter, label: "Tail Sampling" },
      { to: "/app/metrics-pipeline", icon: BarChart3, label: "Metrics Pipeline" },
      { to: "/app/logs-pipeline", icon: ScrollText, label: "Logs Pipeline" },
    ],
  },
  {
    id: "enterprise",
    label: "Enterprise",
    color: "text-sky-400",
    items: [
      { to: "/app/chatops", icon: MessageSquare, label: "ChatOps" },
      { to: "/app/integrations", icon: Plug, label: "Integrations" },
      { to: "/app/automation", icon: Zap, label: "Automation Rules" },
    ],
  },
  {
    id: "platform",
    label: "Platform",
    color: "text-gray-400",
    items: [
      { to: "/app/marketplace", icon: Store, label: "Marketplace" },
      { to: "/app/onboarding", icon: Rocket, label: "Onboarding" },
      { to: "/app/infra-as-code", icon: Code, label: "Infra as Code" },
      { to: "/app/api-keys", icon: Key, label: "API Keys" },
      { to: "/app/mcp-servers", icon: Server, label: "MCP Servers" },
      { to: "/app/settings", icon: Settings, label: "Settings" },
      { to: "/app/users", icon: Users, label: "Users" },
    ],
  },
];
