import { useState } from "react";
import {
  Server,
  AlertTriangle,
  ShieldCheck,
  Key,
  Package,
  Lock,
  Unlock,
  CheckCircle,
  XCircle,
  ExternalLink,
  ScanSearch,
  Eye,
  Wrench,
  SplitSquareVertical,
  Plus,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type TabId = "servers" | "godkeys" | "supply_chain" | "zero_trust";
type Transport = "stdio" | "HTTP SSE" | "WebSocket";
type TrustLevel = "high" | "medium" | "low" | "untrusted";

interface MCPServer {
  id: string;
  name: string;
  endpoint: string;
  transport: Transport;
  authType: string;
  toolsExposed: number;
  downstreamResources: number;
  riskScore: number;
  trustLevel: TrustLevel;
  owner: string;
}

interface GodKeyRisk {
  id: string;
  serverName: string;
  riskScore: number;
  credentialScope: string;
  blastRadius: number;
  downstreamResources: string[];
  recommendedAction: string;
  actionType: "scope_down" | "add_auth" | "split_server";
}

interface SupplyChainVuln {
  id: string;
  component: string;
  type: "npm" | "pip" | "docker";
  version: string;
  cveIds: string[];
  severity: "critical" | "high" | "medium" | "low";
  fixAvailable: boolean;
  fixedVersion: string | null;
  scanStatus: "new" | "triaged" | "in_progress" | "resolved";
}

interface ZeroTrustCheck {
  serverId: string;
  serverName: string;
  oauth2: boolean;
  tls: boolean;
  certValid: boolean;
  auditLogging: boolean;
  scopedPermissions: boolean;
  compliance: "compliant" | "non_compliant" | "partial";
}

// ── Demo Data ────────────────────────────────────────────────────────
const SERVERS: MCPServer[] = [
  { id: "mcp-001", name: "postgres-mcp", endpoint: "localhost:5432/mcp", transport: "stdio", authType: "Token", toolsExposed: 8, downstreamResources: 12, riskScore: 45, trustLevel: "high", owner: "data-team" },
  { id: "mcp-002", name: "github-mcp", endpoint: "https://mcp.github.internal", transport: "HTTP SSE", authType: "OAuth2", toolsExposed: 15, downstreamResources: 340, riskScore: 62, trustLevel: "medium", owner: "engineering" },
  { id: "mcp-003", name: "slack-mcp", endpoint: "https://slack-mcp.internal", transport: "HTTP SSE", authType: "OAuth2", toolsExposed: 6, downstreamResources: 24, riskScore: 28, trustLevel: "high", owner: "platform-team" },
  { id: "mcp-004", name: "jira-mcp", endpoint: "https://jira-mcp.internal", transport: "HTTP SSE", authType: "API Key", toolsExposed: 10, downstreamResources: 180, riskScore: 38, trustLevel: "medium", owner: "engineering" },
  { id: "mcp-005", name: "aws-s3-mcp", endpoint: "localhost:8080/s3", transport: "stdio", authType: "IAM Role", toolsExposed: 12, downstreamResources: 85, riskScore: 78, trustLevel: "low", owner: "infra-team" },
  { id: "mcp-006", name: "google-drive-mcp", endpoint: "https://drive-mcp.internal", transport: "HTTP SSE", authType: "Service Account", toolsExposed: 9, downstreamResources: 2400, riskScore: 85, trustLevel: "low", owner: "it-ops" },
  { id: "mcp-007", name: "confluence-mcp", endpoint: "https://confluence-mcp.internal", transport: "HTTP SSE", authType: "API Key", toolsExposed: 7, downstreamResources: 560, riskScore: 42, trustLevel: "medium", owner: "engineering" },
  { id: "mcp-008", name: "linear-mcp", endpoint: "https://linear-mcp.internal", transport: "WebSocket", authType: "OAuth2", toolsExposed: 8, downstreamResources: 45, riskScore: 22, trustLevel: "high", owner: "product-team" },
  { id: "mcp-009", name: "datadog-mcp", endpoint: "https://dd-mcp.internal", transport: "HTTP SSE", authType: "API Key", toolsExposed: 11, downstreamResources: 150, riskScore: 35, trustLevel: "medium", owner: "sre-team" },
  { id: "mcp-010", name: "vault-mcp", endpoint: "localhost:8200/mcp", transport: "stdio", authType: "mTLS", toolsExposed: 5, downstreamResources: 920, riskScore: 91, trustLevel: "low", owner: "security-team" },
  { id: "mcp-011", name: "kubernetes-mcp", endpoint: "https://k8s-mcp.internal", transport: "HTTP SSE", authType: "ServiceAccount", toolsExposed: 18, downstreamResources: 240, riskScore: 72, trustLevel: "low", owner: "infra-team" },
  { id: "mcp-012", name: "internal-tools-mcp", endpoint: "localhost:9090/mcp", transport: "stdio", authType: "None", toolsExposed: 22, downstreamResources: 65, riskScore: 88, trustLevel: "untrusted", owner: "unknown" },
];

const GOD_KEYS: GodKeyRisk[] = [
  {
    id: "gk-001",
    serverName: "vault-mcp",
    riskScore: 91,
    credentialScope: "Root token with full read/write access to all Vault paths including PKI, transit, and secrets engines",
    blastRadius: 920,
    downstreamResources: ["PostgreSQL credentials", "AWS IAM keys", "TLS certificates", "Encryption keys", "API tokens (47 services)", "SSH CA"],
    recommendedAction: "Scope down to path-specific policies; remove root token access",
    actionType: "scope_down",
  },
  {
    id: "gk-002",
    serverName: "google-drive-mcp",
    riskScore: 85,
    credentialScope: "Service account with domain-wide delegation; can access all user files across the organization",
    blastRadius: 2400,
    downstreamResources: ["All Drive files", "Shared drives (34)", "User documents", "Spreadsheets with PII", "HR confidential folder"],
    recommendedAction: "Replace domain-wide delegation with per-user OAuth consent; add DLP classification",
    actionType: "add_auth",
  },
  {
    id: "gk-003",
    serverName: "internal-tools-mcp",
    riskScore: 88,
    credentialScope: "No authentication; exposes 22 tools including shell execution, file system access, and database queries",
    blastRadius: 65,
    downstreamResources: ["Shell execution", "File system (read/write)", "Database queries", "Network scanning", "Process management", "Log access"],
    recommendedAction: "Split into domain-specific servers; add mTLS authentication to each",
    actionType: "split_server",
  },
];

const SUPPLY_CHAIN: SupplyChainVuln[] = [
  { id: "sc-001", component: "@modelcontextprotocol/sdk", type: "npm", version: "1.2.3", cveIds: ["CVE-2026-1234"], severity: "high", fixAvailable: true, fixedVersion: "1.2.5", scanStatus: "triaged" },
  { id: "sc-002", component: "mcp-server-postgres", type: "npm", version: "0.8.1", cveIds: ["CVE-2026-5678"], severity: "critical", fixAvailable: true, fixedVersion: "0.8.3", scanStatus: "in_progress" },
  { id: "sc-003", component: "langchain-mcp", type: "pip", version: "0.3.2", cveIds: ["CVE-2026-9012"], severity: "medium", fixAvailable: false, fixedVersion: null, scanStatus: "triaged" },
  { id: "sc-004", component: "mcp-proxy", type: "docker", version: "2.1.0", cveIds: ["CVE-2026-3456", "CVE-2026-3457"], severity: "high", fixAvailable: true, fixedVersion: "2.1.2", scanStatus: "new" },
  { id: "sc-005", component: "fastmcp", type: "pip", version: "1.0.4", cveIds: ["CVE-2026-7890"], severity: "low", fixAvailable: true, fixedVersion: "1.0.5", scanStatus: "resolved" },
  { id: "sc-006", component: "mcp-server-github", type: "npm", version: "0.5.0", cveIds: ["CVE-2026-2345"], severity: "medium", fixAvailable: true, fixedVersion: "0.5.2", scanStatus: "triaged" },
  { id: "sc-007", component: "mcp-transport-sse", type: "npm", version: "1.1.0", cveIds: ["CVE-2026-6789"], severity: "high", fixAvailable: false, fixedVersion: null, scanStatus: "new" },
  { id: "sc-008", component: "vault-mcp-plugin", type: "docker", version: "0.2.1", cveIds: ["CVE-2026-4567"], severity: "critical", fixAvailable: true, fixedVersion: "0.2.4", scanStatus: "in_progress" },
];

const ZERO_TRUST: ZeroTrustCheck[] = [
  { serverId: "mcp-001", serverName: "postgres-mcp", oauth2: false, tls: true, certValid: true, auditLogging: true, scopedPermissions: true, compliance: "partial" },
  { serverId: "mcp-002", serverName: "github-mcp", oauth2: true, tls: true, certValid: true, auditLogging: true, scopedPermissions: true, compliance: "compliant" },
  { serverId: "mcp-003", serverName: "slack-mcp", oauth2: true, tls: true, certValid: true, auditLogging: true, scopedPermissions: true, compliance: "compliant" },
  { serverId: "mcp-004", serverName: "jira-mcp", oauth2: false, tls: true, certValid: true, auditLogging: false, scopedPermissions: true, compliance: "partial" },
  { serverId: "mcp-005", serverName: "aws-s3-mcp", oauth2: false, tls: false, certValid: false, auditLogging: true, scopedPermissions: false, compliance: "non_compliant" },
  { serverId: "mcp-006", serverName: "google-drive-mcp", oauth2: false, tls: true, certValid: true, auditLogging: false, scopedPermissions: false, compliance: "non_compliant" },
  { serverId: "mcp-007", serverName: "confluence-mcp", oauth2: false, tls: true, certValid: true, auditLogging: true, scopedPermissions: true, compliance: "partial" },
  { serverId: "mcp-008", serverName: "linear-mcp", oauth2: true, tls: true, certValid: true, auditLogging: true, scopedPermissions: true, compliance: "compliant" },
  { serverId: "mcp-009", serverName: "datadog-mcp", oauth2: false, tls: true, certValid: true, auditLogging: true, scopedPermissions: true, compliance: "partial" },
  { serverId: "mcp-010", serverName: "vault-mcp", oauth2: false, tls: true, certValid: true, auditLogging: true, scopedPermissions: false, compliance: "partial" },
  { serverId: "mcp-011", serverName: "kubernetes-mcp", oauth2: false, tls: true, certValid: false, auditLogging: true, scopedPermissions: false, compliance: "non_compliant" },
  { serverId: "mcp-012", serverName: "internal-tools-mcp", oauth2: false, tls: false, certValid: false, auditLogging: false, scopedPermissions: false, compliance: "non_compliant" },
];

// ── Helpers ──────────────────────────────────────────────────────────
const TABS: { id: TabId; label: string }[] = [
  { id: "servers", label: "Servers" },
  { id: "godkeys", label: "God Keys" },
  { id: "supply_chain", label: "Supply Chain" },
  { id: "zero_trust", label: "Zero Trust" },
];

const TRUST_COLORS: Record<TrustLevel, string> = {
  high: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15",
  medium: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
  low: "bg-orange-500/[0.08] text-orange-400 ring-orange-500/15",
  untrusted: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
};

const SEVERITY_BADGES: Record<string, string> = {
  critical: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
  high: "bg-orange-500/[0.08] text-orange-400 ring-orange-500/15",
  medium: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
  low: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15",
};

const TYPE_BADGES: Record<string, string> = {
  npm: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
  pip: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15",
  docker: "bg-cyan-500/[0.08] text-cyan-400 ring-cyan-500/15",
};

const ACTION_ICONS: Record<string, typeof Wrench> = {
  scope_down: Wrench,
  add_auth: Plus,
  split_server: SplitSquareVertical,
};

const ACTION_LABELS: Record<string, string> = {
  scope_down: "Scope Down",
  add_auth: "Add Auth",
  split_server: "Split Server",
};

function riskColor(score: number) {
  if (score > 80) return "text-red-400";
  if (score >= 50) return "text-amber-400";
  return "text-emerald-400";
}

function BoolIcon({ value }: { value: boolean }) {
  return value ? (
    <CheckCircle className="h-4 w-4 text-emerald-400" />
  ) : (
    <XCircle className="h-4 w-4 text-red-400" />
  );
}

// ── Component ────────────────────────────────────────────────────────
export default function MCPSecurity() {
  const [tab, setTab] = useState<TabId>("servers");

  const godKeyCount = GOD_KEYS.length;
  const vulnCount = SUPPLY_CHAIN.filter((v) => v.scanStatus !== "resolved").length;
  const compliantCount = ZERO_TRUST.filter((z) => z.compliance === "compliant").length;
  const compliancePct = Math.round((compliantCount / ZERO_TRUST.length) * 100);

  return (
    <div className="space-y-6">
      <PageHeader
        title="MCP Security"
        badge={{ label: `${SERVERS.length} Servers`, variant: "info" }}
        description="Security posture for your Model Context Protocol ecosystem"
      />

      {/* Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="MCP Servers" value={SERVERS.length} icon={<Server className="h-5 w-5" />} change={9.1} />
        <MetricCard label="God Key Risks" value={godKeyCount} icon={<Key className="h-5 w-5" />} change={0} />
        <MetricCard label="Supply Chain Vulns" value={vulnCount} icon={<Package className="h-5 w-5" />} change={-12.5} />
        <MetricCard label="Zero-Trust Compliance" value={`${compliancePct}%`} icon={<ShieldCheck className="h-5 w-5" />} change={8.3} />
      </div>

      {/* Tab Bar */}
      <div className="flex gap-1 rounded-lg border border-white/[0.06] bg-surface-1 p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              "rounded-md px-4 py-2 text-sm font-medium transition-colors",
              tab === t.id
                ? "bg-surface-3 text-gray-100 shadow-sm"
                : "text-gray-400 hover:text-gray-200",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Servers Tab */}
      {tab === "servers" && (
        <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.04] text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              <tr>
                <th className="px-5 py-3.5">Server</th>
                <th className="px-5 py-3.5">Transport</th>
                <th className="px-5 py-3.5">Auth</th>
                <th className="px-5 py-3.5">Tools</th>
                <th className="px-5 py-3.5">Resources</th>
                <th className="px-5 py-3.5">Risk</th>
                <th className="px-5 py-3.5">Trust</th>
                <th className="px-5 py-3.5">Owner</th>
                <th className="px-5 py-3.5">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {SERVERS.map((srv) => (
                <tr key={srv.id} className="hover:bg-surface-3">
                  <td className="px-5 py-3.5">
                    <div>
                      <p className="font-mono text-[13px] font-medium text-gray-100">{srv.name}</p>
                      <p className="mt-0.5 text-[11px] text-gray-600">{srv.endpoint}</p>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="inline-flex rounded-md bg-white/[0.04] px-2 py-0.5 text-[11px] font-medium text-gray-400 ring-1 ring-inset ring-white/[0.06]">
                      {srv.transport}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-gray-300">
                    <span className="flex items-center gap-1">
                      {srv.authType === "None" ? <Unlock className="h-3 w-3 text-red-400" /> : <Lock className="h-3 w-3 text-emerald-400" />}
                      {srv.authType}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-gray-300">{srv.toolsExposed}</td>
                  <td className="px-5 py-3.5 text-gray-300">{srv.downstreamResources}</td>
                  <td className="px-5 py-3.5">
                    <span className={clsx("font-semibold", riskColor(srv.riskScore))}>{srv.riskScore}</span>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", TRUST_COLORS[srv.trustLevel])}>
                      {srv.trustLevel}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-gray-400">{srv.owner}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex gap-2">
                      <button className="text-[12px] font-medium text-brand-400 hover:text-brand-300">
                        <ScanSearch className="mr-1 inline h-3 w-3" /> Scan
                      </button>
                      <button className="text-[12px] font-medium text-gray-500 hover:text-gray-300">
                        <Eye className="mr-1 inline h-3 w-3" /> View
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* God Keys Tab */}
      {tab === "godkeys" && (
        <div className="space-y-4">
          {GOD_KEYS.map((gk) => {
            const ActionIcon = ACTION_ICONS[gk.actionType];
            return (
              <div
                key={gk.id}
                className="overflow-hidden rounded-xl border border-red-500/20 bg-surface-2 shadow-depth transition-colors hover:border-red-500/30"
              >
                {/* Header */}
                <div className="border-b border-red-500/10 bg-red-500/[0.03] px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="h-5 w-5 text-red-400" />
                      <span className="font-mono text-sm font-semibold text-gray-100">{gk.serverName}</span>
                      <span className={clsx("text-sm font-bold", riskColor(gk.riskScore))}>Risk: {gk.riskScore}</span>
                    </div>
                    <button className="flex items-center gap-1.5 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-1.5 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/[0.12]">
                      <ActionIcon className="h-3.5 w-3.5" />
                      {ACTION_LABELS[gk.actionType]}
                    </button>
                  </div>
                </div>

                {/* Body */}
                <div className="p-6">
                  <div className="mb-4">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">Credential Scope</p>
                    <p className="mt-1 text-[13px] text-gray-300">{gk.credentialScope}</p>
                  </div>

                  <div className="mb-4">
                    <div className="flex items-center gap-2">
                      <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">Blast Radius</p>
                      <span className="inline-flex rounded-md bg-red-500/[0.08] px-2 py-0.5 text-[11px] font-bold text-red-400 ring-1 ring-inset ring-red-500/15">
                        {gk.blastRadius} resources
                      </span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {gk.downstreamResources.map((res) => (
                        <span
                          key={res}
                          className="inline-flex rounded-md bg-white/[0.04] px-2 py-0.5 text-[11px] text-gray-400 ring-1 ring-inset ring-white/[0.06]"
                        >
                          {res}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">Recommended Action</p>
                    <p className="mt-1 text-[13px] text-brand-400">{gk.recommendedAction}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Supply Chain Tab */}
      {tab === "supply_chain" && (
        <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.04] text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              <tr>
                <th className="px-5 py-3.5">Component</th>
                <th className="px-5 py-3.5">Type</th>
                <th className="px-5 py-3.5">Version</th>
                <th className="px-5 py-3.5">CVEs</th>
                <th className="px-5 py-3.5">Severity</th>
                <th className="px-5 py-3.5">Fix</th>
                <th className="px-5 py-3.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {SUPPLY_CHAIN.map((vuln) => (
                <tr key={vuln.id} className="hover:bg-surface-3">
                  <td className="px-5 py-3.5 font-mono text-[13px] font-medium text-gray-100">{vuln.component}</td>
                  <td className="px-5 py-3.5">
                    <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", TYPE_BADGES[vuln.type])}>
                      {vuln.type}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 font-mono text-[12px] text-gray-400">{vuln.version}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex flex-wrap gap-1">
                      {vuln.cveIds.map((cve) => (
                        <span key={cve} className="inline-flex items-center gap-1 text-[12px] font-medium text-brand-400 hover:text-brand-300">
                          {cve} <ExternalLink className="h-2.5 w-2.5" />
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", SEVERITY_BADGES[vuln.severity])}>
                      {vuln.severity}
                    </span>
                  </td>
                  <td className="px-5 py-3.5">
                    {vuln.fixAvailable ? (
                      <span className="text-emerald-400">
                        <CheckCircle className="mr-1 inline h-3 w-3" />
                        <span className="font-mono text-[12px]">{vuln.fixedVersion}</span>
                      </span>
                    ) : (
                      <span className="text-gray-600">
                        <XCircle className="mr-1 inline h-3 w-3" /> No fix
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3.5">
                    <StatusBadge status={vuln.scanStatus} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Zero Trust Tab */}
      {tab === "zero_trust" && (
        <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.04] text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              <tr>
                <th className="px-5 py-3.5">Server</th>
                <th className="px-5 py-3.5 text-center">OAuth2</th>
                <th className="px-5 py-3.5 text-center">TLS</th>
                <th className="px-5 py-3.5 text-center">Cert Valid</th>
                <th className="px-5 py-3.5 text-center">Audit Log</th>
                <th className="px-5 py-3.5 text-center">Scoped Perms</th>
                <th className="px-5 py-3.5">Compliance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {ZERO_TRUST.map((zt) => (
                <tr key={zt.serverId} className="hover:bg-surface-3">
                  <td className="px-5 py-3.5 font-mono text-[13px] font-medium text-gray-100">{zt.serverName}</td>
                  <td className="px-5 py-3.5 text-center"><BoolIcon value={zt.oauth2} /></td>
                  <td className="px-5 py-3.5 text-center"><BoolIcon value={zt.tls} /></td>
                  <td className="px-5 py-3.5 text-center"><BoolIcon value={zt.certValid} /></td>
                  <td className="px-5 py-3.5 text-center"><BoolIcon value={zt.auditLogging} /></td>
                  <td className="px-5 py-3.5 text-center"><BoolIcon value={zt.scopedPermissions} /></td>
                  <td className="px-5 py-3.5">
                    <StatusBadge status={zt.compliance} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
