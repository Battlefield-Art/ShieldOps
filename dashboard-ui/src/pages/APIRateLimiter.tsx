import { useState } from "react";
import {
  Shield,
  AlertTriangle,
  Activity,
  Ban,
  Gauge,
  Clock,
  Globe,
  Search,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// -- Types --
type TabId = "clients" | "detections" | "rules" | "traffic";
type AbusePattern =
  | "credential_stuffing"
  | "api_scraping"
  | "brute_force"
  | "enumeration"
  | "distributed_attack"
  | "normal";
type ActionType = "allow" | "throttle" | "block" | "challenge" | "shadow_ban";
type Severity = "critical" | "high" | "medium" | "low";

interface ClientEntry {
  id: string;
  clientId: string;
  ip: string;
  rpm: number;
  endpoints: number;
  authFailures: number;
  riskScore: number;
  action: ActionType;
  country: string;
}

interface DetectionEntry {
  id: string;
  clientId: string;
  pattern: AbusePattern;
  severity: Severity;
  confidence: number;
  description: string;
  requestCount: number;
  timestamp: string;
}

interface RuleEntry {
  id: string;
  clientId: string;
  endpointPattern: string;
  rpm: number;
  burstLimit: number;
  action: ActionType;
  reason: string;
  adaptive: boolean;
}

interface TrafficEntry {
  id: string;
  timestamp: string;
  clientId: string;
  endpoint: string;
  method: string;
  status: number;
  responseMs: number;
  action: ActionType;
}

// -- Demo Data --
const CLIENTS: ClientEntry[] = [
  { id: "c-001", clientId: "bot-scraper-42", ip: "45.33.32.156", rpm: 342, endpoints: 47, authFailures: 0, riskScore: 92, action: "block", country: "RU" },
  { id: "c-002", clientId: "cred-stuffer-x", ip: "185.220.101.0/24", rpm: 128, endpoints: 2, authFailures: 89, riskScore: 97, action: "block", country: "CN" },
  { id: "c-003", clientId: "api-key-7f3a", ip: "203.0.113.50", rpm: 85, endpoints: 12, authFailures: 3, riskScore: 45, action: "throttle", country: "IN" },
  { id: "c-004", clientId: "mobile-app-v2", ip: "192.168.1.0/24", rpm: 42, endpoints: 8, authFailures: 0, riskScore: 5, action: "allow", country: "US" },
  { id: "c-005", clientId: "partner-sync", ip: "10.0.0.50", rpm: 120, endpoints: 3, authFailures: 0, riskScore: 12, action: "allow", country: "US" },
  { id: "c-006", clientId: "enum-attack-9", ip: "77.88.55.0/24", rpm: 200, endpoints: 35, authFailures: 15, riskScore: 78, action: "challenge", country: "UA" },
  { id: "c-007", clientId: "legit-dashboard", ip: "172.16.0.10", rpm: 18, endpoints: 6, authFailures: 0, riskScore: 2, action: "allow", country: "US" },
  { id: "c-008", clientId: "slow-probe-z", ip: "198.51.100.22", rpm: 8, endpoints: 28, authFailures: 4, riskScore: 61, action: "throttle", country: "BR" },
];

const DETECTIONS: DetectionEntry[] = [
  { id: "d-001", clientId: "cred-stuffer-x", pattern: "credential_stuffing", severity: "critical", confidence: 0.97, description: "89 auth failures from rotating IP block 185.220.101.0/24, sequential username patterns detected", requestCount: 1240, timestamp: "2026-03-28T14:32:00Z" },
  { id: "d-002", clientId: "bot-scraper-42", pattern: "api_scraping", severity: "critical", confidence: 0.94, description: "Systematic enumeration of 47 endpoints at 342 rpm, harvesting product catalog data", requestCount: 8420, timestamp: "2026-03-28T14:28:00Z" },
  { id: "d-003", clientId: "enum-attack-9", pattern: "enumeration", severity: "high", confidence: 0.85, description: "User ID enumeration via /api/v1/users/{id} with sequential IDs", requestCount: 3200, timestamp: "2026-03-28T14:15:00Z" },
  { id: "d-004", clientId: "cred-stuffer-x", pattern: "distributed_attack", severity: "critical", confidence: 0.88, description: "Same credential stuffing pattern from 12 distinct IPs across 3 countries", requestCount: 4800, timestamp: "2026-03-28T14:10:00Z" },
  { id: "d-005", clientId: "slow-probe-z", pattern: "api_scraping", severity: "medium", confidence: 0.72, description: "Low-rate scraping of 28 endpoints, evading simple rate limits", requestCount: 560, timestamp: "2026-03-28T13:45:00Z" },
  { id: "d-006", clientId: "enum-attack-9", pattern: "brute_force", severity: "high", confidence: 0.81, description: "15 auth failures against admin endpoints from 2 IPs", requestCount: 890, timestamp: "2026-03-28T13:30:00Z" },
];

const RULES: RuleEntry[] = [
  { id: "r-001", clientId: "cred-stuffer-x", endpointPattern: "*", rpm: 0, burstLimit: 0, action: "block", reason: "credential_stuffing: 89 auth failures", adaptive: true },
  { id: "r-002", clientId: "bot-scraper-42", endpointPattern: "*", rpm: 0, burstLimit: 0, action: "block", reason: "api_scraping: 47 endpoints at 342 rpm", adaptive: true },
  { id: "r-003", clientId: "enum-attack-9", endpointPattern: "/api/v1/users/*", rpm: 5, burstLimit: 10, action: "challenge", reason: "enumeration: sequential user ID probing", adaptive: true },
  { id: "r-004", clientId: "api-key-7f3a", endpointPattern: "*", rpm: 30, burstLimit: 60, action: "throttle", reason: "elevated_risk: approaching rate threshold", adaptive: true },
  { id: "r-005", clientId: "slow-probe-z", endpointPattern: "*", rpm: 15, burstLimit: 30, action: "throttle", reason: "api_scraping: low-rate enumeration", adaptive: true },
  { id: "r-006", clientId: "mobile-app-v2", endpointPattern: "*", rpm: 120, burstLimit: 240, action: "allow", reason: "clean_client_adaptive_boost", adaptive: true },
  { id: "r-007", clientId: "partner-sync", endpointPattern: "/api/v1/sync/*", rpm: 200, burstLimit: 400, action: "allow", reason: "trusted_partner_elevated_limit", adaptive: false },
  { id: "r-008", clientId: "*", endpointPattern: "/api/v1/auth/login", rpm: 10, burstLimit: 20, action: "throttle", reason: "global_auth_protection", adaptive: false },
];

const TRAFFIC: TrafficEntry[] = [
  { id: "t-001", timestamp: "14:32:45", clientId: "cred-stuffer-x", endpoint: "/api/v1/auth/login", method: "POST", status: 401, responseMs: 12, action: "block" },
  { id: "t-002", timestamp: "14:32:44", clientId: "bot-scraper-42", endpoint: "/api/v1/products/8842", method: "GET", status: 429, responseMs: 2, action: "block" },
  { id: "t-003", timestamp: "14:32:43", clientId: "mobile-app-v2", endpoint: "/api/v1/dashboard", method: "GET", status: 200, responseMs: 45, action: "allow" },
  { id: "t-004", timestamp: "14:32:42", clientId: "enum-attack-9", endpoint: "/api/v1/users/10442", method: "GET", status: 403, responseMs: 8, action: "challenge" },
  { id: "t-005", timestamp: "14:32:41", clientId: "partner-sync", endpoint: "/api/v1/sync/orders", method: "POST", status: 200, responseMs: 120, action: "allow" },
  { id: "t-006", timestamp: "14:32:40", clientId: "api-key-7f3a", endpoint: "/api/v1/reports", method: "GET", status: 200, responseMs: 85, action: "throttle" },
  { id: "t-007", timestamp: "14:32:39", clientId: "slow-probe-z", endpoint: "/api/v1/settings/billing", method: "GET", status: 200, responseMs: 32, action: "throttle" },
  { id: "t-008", timestamp: "14:32:38", clientId: "legit-dashboard", endpoint: "/api/v1/metrics", method: "GET", status: 200, responseMs: 22, action: "allow" },
  { id: "t-009", timestamp: "14:32:37", clientId: "cred-stuffer-x", endpoint: "/api/v1/auth/login", method: "POST", status: 401, responseMs: 11, action: "block" },
  { id: "t-010", timestamp: "14:32:36", clientId: "bot-scraper-42", endpoint: "/api/v1/products/8843", method: "GET", status: 429, responseMs: 1, action: "block" },
  { id: "t-011", timestamp: "14:32:35", clientId: "mobile-app-v2", endpoint: "/api/v1/notifications", method: "GET", status: 200, responseMs: 38, action: "allow" },
  { id: "t-012", timestamp: "14:32:34", clientId: "enum-attack-9", endpoint: "/api/v1/users/10443", method: "GET", status: 403, responseMs: 7, action: "challenge" },
];

// -- Helpers --
const TABS: { id: TabId; label: string }[] = [
  { id: "clients", label: "Clients" },
  { id: "detections", label: "Detections" },
  { id: "rules", label: "Rules" },
  { id: "traffic", label: "Live Traffic" },
];

const ACTION_COLORS: Record<ActionType, string> = {
  allow: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15",
  throttle: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
  block: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
  challenge: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15",
  shadow_ban: "bg-gray-500/[0.08] text-gray-400 ring-gray-500/15",
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
  high: "bg-orange-500/[0.08] text-orange-400 ring-orange-500/15",
  medium: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
  low: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15",
};

const PATTERN_LABELS: Record<AbusePattern, string> = {
  credential_stuffing: "Credential Stuffing",
  api_scraping: "API Scraping",
  brute_force: "Brute Force",
  enumeration: "Enumeration",
  distributed_attack: "Distributed Attack",
  normal: "Normal",
};

function riskColor(score: number) {
  if (score > 80) return "text-red-400";
  if (score >= 50) return "text-amber-400";
  return "text-emerald-400";
}

function statusCode(code: number) {
  if (code >= 400) return "text-red-400";
  if (code >= 300) return "text-amber-400";
  return "text-emerald-400";
}

// -- Component --
export default function APIRateLimiter() {
  const [tab, setTab] = useState<TabId>("clients");

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Rate Limiter"
        badge={{ label: "8 Clients Tracked", variant: "info" }}
        description="Intelligent rate limiting with abuse pattern detection and adaptive enforcement"
      />

      {/* Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Requests Analyzed (1h)" value="18,420" icon={<Activity className="h-5 w-5" />} change={8.4} />
        <MetricCard label="Abuse Patterns Detected" value={6} icon={<AlertTriangle className="h-5 w-5" />} change={-15.0} />
        <MetricCard label="Clients Blocked" value={2} icon={<Ban className="h-5 w-5" />} change={0} />
        <MetricCard label="Avg Response (ms)" value="1.8" icon={<Gauge className="h-5 w-5" />} change={-22.5} />
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

      {/* Clients Tab */}
      {tab === "clients" && (
        <div className="overflow-hidden rounded-lg border border-white/[0.06]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.06] bg-surface-1">
              <tr>
                <th className="px-4 py-3 font-medium text-gray-400">Client</th>
                <th className="px-4 py-3 font-medium text-gray-400">IP</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">RPM</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">Endpoints</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">Auth Fails</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">Risk</th>
                <th className="px-4 py-3 font-medium text-gray-400">Country</th>
                <th className="px-4 py-3 font-medium text-gray-400">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {CLIENTS.map((c) => (
                <tr key={c.id} className="hover:bg-white/[0.02]">
                  <td className="px-4 py-3 font-mono text-xs text-gray-200">{c.clientId}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">{c.ip}</td>
                  <td className="px-4 py-3 text-right text-gray-200">{c.rpm}</td>
                  <td className="px-4 py-3 text-right text-gray-300">{c.endpoints}</td>
                  <td className="px-4 py-3 text-right">
                    <span className={c.authFailures > 10 ? "text-red-400" : "text-gray-300"}>{c.authFailures}</span>
                  </td>
                  <td className={clsx("px-4 py-3 text-right font-semibold", riskColor(c.riskScore))}>{c.riskScore}</td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1 text-gray-400">
                      <Globe className="h-3 w-3" /> {c.country}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", ACTION_COLORS[c.action])}>
                      {c.action}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Detections Tab */}
      {tab === "detections" && (
        <div className="space-y-3">
          {DETECTIONS.map((d) => (
            <div key={d.id} className="rounded-lg border border-white/[0.06] bg-surface-1 p-4">
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", SEVERITY_COLORS[d.severity])}>
                      {d.severity}
                    </span>
                    <span className="text-sm font-medium text-gray-200">{PATTERN_LABELS[d.pattern]}</span>
                    <span className="font-mono text-xs text-gray-500">{d.clientId}</span>
                  </div>
                  <p className="text-sm text-gray-400">{d.description}</p>
                </div>
                <div className="text-right">
                  <div className={clsx("text-lg font-semibold", riskColor(d.confidence * 100))}>
                    {(d.confidence * 100).toFixed(0)}%
                  </div>
                  <div className="text-xs text-gray-500">confidence</div>
                </div>
              </div>
              <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
                <span className="flex items-center gap-1"><Activity className="h-3 w-3" /> {d.requestCount.toLocaleString()} requests</span>
                <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {new Date(d.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Rules Tab */}
      {tab === "rules" && (
        <div className="overflow-hidden rounded-lg border border-white/[0.06]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.06] bg-surface-1">
              <tr>
                <th className="px-4 py-3 font-medium text-gray-400">Client</th>
                <th className="px-4 py-3 font-medium text-gray-400">Endpoint</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">RPM Limit</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">Burst</th>
                <th className="px-4 py-3 font-medium text-gray-400">Action</th>
                <th className="px-4 py-3 font-medium text-gray-400">Reason</th>
                <th className="px-4 py-3 font-medium text-gray-400">Type</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {RULES.map((r) => (
                <tr key={r.id} className="hover:bg-white/[0.02]">
                  <td className="px-4 py-3 font-mono text-xs text-gray-200">{r.clientId}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">{r.endpointPattern}</td>
                  <td className="px-4 py-3 text-right text-gray-200">{r.rpm}</td>
                  <td className="px-4 py-3 text-right text-gray-300">{r.burstLimit}</td>
                  <td className="px-4 py-3">
                    <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", ACTION_COLORS[r.action])}>
                      {r.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400 max-w-xs truncate">{r.reason}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={r.adaptive ? "active" : "info"} label={r.adaptive ? "Adaptive" : "Manual"} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Live Traffic Tab */}
      {tab === "traffic" && (
        <div className="overflow-hidden rounded-lg border border-white/[0.06]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.06] bg-surface-1">
              <tr>
                <th className="px-4 py-3 font-medium text-gray-400">Time</th>
                <th className="px-4 py-3 font-medium text-gray-400">Client</th>
                <th className="px-4 py-3 font-medium text-gray-400">Method</th>
                <th className="px-4 py-3 font-medium text-gray-400">Endpoint</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">Status</th>
                <th className="px-4 py-3 font-medium text-gray-400 text-right">Latency</th>
                <th className="px-4 py-3 font-medium text-gray-400">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {TRAFFIC.map((t) => (
                <tr key={t.id} className="hover:bg-white/[0.02]">
                  <td className="px-4 py-3 font-mono text-xs text-gray-500">{t.timestamp}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-200">{t.clientId}</td>
                  <td className="px-4 py-3 text-xs font-medium text-gray-300">{t.method}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">{t.endpoint}</td>
                  <td className={clsx("px-4 py-3 text-right font-mono text-xs", statusCode(t.status))}>{t.status}</td>
                  <td className="px-4 py-3 text-right text-gray-300">{t.responseMs}ms</td>
                  <td className="px-4 py-3">
                    <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", ACTION_COLORS[t.action])}>
                      {t.action}
                    </span>
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
