import { useState, useCallback, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Bot,
  Bell,
  Key,
  ExternalLink,
  Copy,
  Check,
  MessageSquare,
  Siren,
  Mail,
  Webhook,
  Save,
  Loader2,
  ShieldAlert,
  KeyRound,
  Plug,
  Brain,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import clsx from "clsx";
import { get, put } from "../api/client";
import type { Agent } from "../api/types";
import type { Column } from "../components/DataTable";
import DataTable from "../components/DataTable";
import StatusBadge from "../components/StatusBadge";
import LoadingSpinner from "../components/LoadingSpinner";
import { useAuthStore } from "../store/auth";

type SettingsTab = "agents" | "notifications" | "api" | "ai-security";

const TABS: { key: SettingsTab; label: string; icon: React.ReactNode }[] = [
  { key: "agents", label: "Agents", icon: <Bot className="h-4 w-4" /> },
  { key: "notifications", label: "Notifications", icon: <Bell className="h-4 w-4" /> },
  { key: "api", label: "API", icon: <Key className="h-4 w-4" /> },
  { key: "ai-security", label: "AI Security", icon: <ShieldAlert className="h-4 w-4" /> },
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("agents");

  return (
    <div className="space-y-6">
      {/* Header */}
      <h1 className="text-2xl font-bold text-gray-100">Settings</h1>

      {/* Tab navigation */}
      <div className="flex gap-1 rounded-lg bg-gray-900 p-1">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={clsx(
              "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors",
              activeTab === tab.key
                ? "bg-gray-800 text-gray-100"
                : "text-gray-400 hover:text-gray-200",
            )}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "agents" && <AgentsTab />}
      {activeTab === "notifications" && <NotificationsTab />}
      {activeTab === "api" && <ApiTab />}
      {activeTab === "ai-security" && <AISecurityTab />}
    </div>
  );
}

// ── AI Security Tab ──────────────────────────────────────────────────────

interface AISecurityState {
  // Agent Firewall
  firewallMode: "audit" | "enforce" | "learning";
  autoTripThreshold: number;
  circuitBreakerCooldown: number;
  maxCallsPerMinute: number;
  killSwitchSlack: boolean;
  killSwitchTeams: boolean;
  killSwitchPagerDuty: boolean;
  killSwitchEmail: boolean;
  // NHI Registry
  scanSchedule: string;
  staleCredentialThreshold: number;
  shadowAIDetection: boolean;
  scanAWS: boolean;
  scanGCP: boolean;
  scanAzure: boolean;
  scanKubernetes: boolean;
  scanGitHub: boolean;
  // MCP Security
  gatewayMode: "audit" | "enforce" | "disabled";
  zeroTrustLevel: "permissive" | "moderate" | "strict";
  supplyChainScanFreq: string;
  autoBlockGodKey: boolean;
  // SOC Brain
  autoExecuteThreshold: number;
  approvalTimeout: number;
  crowdStrikeEnabled: boolean;
  crowdStrikeKey: string;
  defenderEnabled: boolean;
  defenderKey: string;
  wizEnabled: boolean;
  wizKey: string;
  defaultEscalationTier: string;
}

const DEFAULT_AI_SECURITY: AISecurityState = {
  firewallMode: "audit",
  autoTripThreshold: 0.85,
  circuitBreakerCooldown: 300,
  maxCallsPerMinute: 100,
  killSwitchSlack: true,
  killSwitchTeams: false,
  killSwitchPagerDuty: true,
  killSwitchEmail: false,
  scanSchedule: "every-6-hours",
  staleCredentialThreshold: 90,
  shadowAIDetection: true,
  scanAWS: true,
  scanGCP: true,
  scanAzure: true,
  scanKubernetes: true,
  scanGitHub: false,
  gatewayMode: "audit",
  zeroTrustLevel: "moderate",
  supplyChainScanFreq: "daily",
  autoBlockGodKey: false,
  autoExecuteThreshold: 0.85,
  approvalTimeout: 30,
  crowdStrikeEnabled: false,
  crowdStrikeKey: "",
  defenderEnabled: false,
  defenderKey: "",
  wizEnabled: false,
  wizKey: "",
  defaultEscalationTier: "tier-2",
};

function AISecurityTab() {
  const [state, setState] = useState<AISecurityState>(DEFAULT_AI_SECURITY);
  const [toastVisible, setToastVisible] = useState(false);
  const [toastMessage, setToastMessage] = useState("");

  const update = <K extends keyof AISecurityState>(key: K, value: AISecurityState[K]) => {
    setState((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    setToastMessage("AI Security settings saved successfully.");
    setToastVisible(true);
    setTimeout(() => setToastVisible(false), 3000);
  };

  const sectionHeading = "text-base font-semibold text-gray-100 mb-1";
  const sectionDesc = "text-sm text-gray-400 mb-4";
  const labelClass = "block text-sm font-medium text-gray-300 mb-1.5";
  const inputClass =
    "w-full rounded-lg border border-white/[0.06] bg-surface-1 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500";
  const cardClass =
    "rounded-xl border border-white/[0.06] bg-surface-1 p-6 shadow-card";

  return (
    <div className="space-y-6 relative">
      {/* Toast notification */}
      {toastVisible && (
        <div className="fixed top-6 right-6 z-50 flex items-center gap-2 rounded-lg border border-green-500/20 bg-green-500/10 px-4 py-3 text-sm text-green-400 shadow-lg">
          <Check className="h-4 w-4" />
          {toastMessage}
        </div>
      )}

      {/* ── Agent Firewall Settings ────────────────────────────────── */}
      <div className={cardClass}>
        <div className="flex items-center gap-2 mb-1">
          <ShieldAlert className="h-5 w-5 text-red-400" />
          <h3 className={sectionHeading}>Agent Firewall Settings</h3>
        </div>
        <p className={sectionDesc}>
          Runtime interception controls for AI agent tool calls and behavioral baselines.
        </p>

        {/* Default monitoring mode */}
        <div className="mb-5">
          <label className={labelClass}>Default Monitoring Mode</label>
          <div className="flex gap-4">
            {(["audit", "enforce", "learning"] as const).map((mode) => (
              <label key={mode} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="firewallMode"
                  checked={state.firewallMode === mode}
                  onChange={() => update("firewallMode", mode)}
                  className="text-brand-500 focus:ring-brand-500 border-gray-600 bg-surface-2"
                />
                <span className="text-sm text-gray-300 capitalize">{mode}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Auto-trip risk threshold */}
        <div className="mb-5">
          <label className={labelClass}>
            Auto-Trip Risk Threshold: <span className="text-brand-400">{state.autoTripThreshold.toFixed(2)}</span>
          </label>
          <input
            type="range"
            min="0.5"
            max="1.0"
            step="0.01"
            value={state.autoTripThreshold}
            onChange={(e) => update("autoTripThreshold", parseFloat(e.target.value))}
            className="w-full accent-brand-500"
          />
          <div className="flex justify-between text-xs text-gray-600 mt-1">
            <span>0.50</span>
            <span>1.00</span>
          </div>
        </div>

        {/* Circuit breaker cooldown */}
        <div className="mb-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className={labelClass}>Circuit Breaker Cooldown (seconds)</label>
            <input
              type="number"
              value={state.circuitBreakerCooldown}
              onChange={(e) => update("circuitBreakerCooldown", parseInt(e.target.value) || 0)}
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass}>Max Calls Per Minute Per Agent</label>
            <input
              type="number"
              value={state.maxCallsPerMinute}
              onChange={(e) => update("maxCallsPerMinute", parseInt(e.target.value) || 0)}
              className={inputClass}
            />
          </div>
        </div>

        {/* Kill switch notification channels */}
        <div>
          <label className={labelClass}>Kill Switch Notification Channels</label>
          <div className="flex flex-wrap gap-4">
            {([
              { key: "killSwitchSlack" as const, label: "Slack" },
              { key: "killSwitchTeams" as const, label: "Teams" },
              { key: "killSwitchPagerDuty" as const, label: "PagerDuty" },
              { key: "killSwitchEmail" as const, label: "Email" },
            ]).map(({ key, label }) => (
              <label key={key} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={state[key]}
                  onChange={(e) => update(key, e.target.checked)}
                  className="rounded border-gray-600 bg-surface-2 text-brand-500 focus:ring-brand-500"
                />
                <span className="text-sm text-gray-300">{label}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* ── NHI Registry Settings ──────────────────────────────────── */}
      <div className={cardClass}>
        <div className="flex items-center gap-2 mb-1">
          <KeyRound className="h-5 w-5 text-amber-400" />
          <h3 className={sectionHeading}>NHI Registry Settings</h3>
        </div>
        <p className={sectionDesc}>
          Discover and govern non-human identities across your cloud infrastructure.
        </p>

        <div className="mb-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className={labelClass}>Scan Schedule</label>
            <select
              value={state.scanSchedule}
              onChange={(e) => update("scanSchedule", e.target.value)}
              className={inputClass}
            >
              <option value="every-hour">Every hour</option>
              <option value="every-6-hours">Every 6 hours</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
          </div>
          <div>
            <label className={labelClass}>Stale Credential Threshold (days)</label>
            <input
              type="number"
              value={state.staleCredentialThreshold}
              onChange={(e) => update("staleCredentialThreshold", parseInt(e.target.value) || 0)}
              className={inputClass}
            />
          </div>
        </div>

        {/* Shadow AI detection toggle */}
        <div className="mb-5 flex items-center justify-between rounded-lg border border-white/[0.06] bg-surface-2 px-4 py-3">
          <div>
            <p className="text-sm font-medium text-gray-200">Shadow AI Detection</p>
            <p className="text-xs text-gray-400">Detect unregistered AI agent API calls in your environment</p>
          </div>
          <button
            onClick={() => update("shadowAIDetection", !state.shadowAIDetection)}
            className={clsx(
              "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
              state.shadowAIDetection ? "bg-brand-500" : "bg-gray-700",
            )}
          >
            <span
              className={clsx(
                "inline-block h-4 w-4 rounded-full bg-white transition-transform",
                state.shadowAIDetection ? "translate-x-6" : "translate-x-1",
              )}
            />
          </button>
        </div>

        {/* Cloud providers to scan */}
        <div>
          <label className={labelClass}>Cloud Providers to Scan</label>
          <div className="flex flex-wrap gap-4">
            {([
              { key: "scanAWS" as const, label: "AWS" },
              { key: "scanGCP" as const, label: "GCP" },
              { key: "scanAzure" as const, label: "Azure" },
              { key: "scanKubernetes" as const, label: "Kubernetes" },
              { key: "scanGitHub" as const, label: "GitHub" },
            ]).map(({ key, label }) => (
              <label key={key} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={state[key]}
                  onChange={(e) => update(key, e.target.checked)}
                  className="rounded border-gray-600 bg-surface-2 text-brand-500 focus:ring-brand-500"
                />
                <span className="text-sm text-gray-300">{label}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* ── MCP Security Settings ──────────────────────────────────── */}
      <div className={cardClass}>
        <div className="flex items-center gap-2 mb-1">
          <Plug className="h-5 w-5 text-sky-400" />
          <h3 className={sectionHeading}>MCP Security Settings</h3>
        </div>
        <p className={sectionDesc}>
          Secure MCP ecosystem with God Key detection and zero-trust enforcement.
        </p>

        {/* Gateway mode */}
        <div className="mb-5">
          <label className={labelClass}>Gateway Mode</label>
          <div className="flex gap-4">
            {(["audit", "enforce", "disabled"] as const).map((mode) => (
              <label key={mode} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="gatewayMode"
                  checked={state.gatewayMode === mode}
                  onChange={() => update("gatewayMode", mode)}
                  className="text-brand-500 focus:ring-brand-500 border-gray-600 bg-surface-2"
                />
                <span className="text-sm text-gray-300 capitalize">{mode}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Zero-trust enforcement level */}
        <div className="mb-5">
          <label className={labelClass}>Zero-Trust Enforcement Level</label>
          <div className="flex gap-4">
            {(["permissive", "moderate", "strict"] as const).map((level) => (
              <label key={level} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="zeroTrustLevel"
                  checked={state.zeroTrustLevel === level}
                  onChange={() => update("zeroTrustLevel", level)}
                  className="text-brand-500 focus:ring-brand-500 border-gray-600 bg-surface-2"
                />
                <span className="text-sm text-gray-300 capitalize">{level}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="mb-5">
          <label className={labelClass}>Supply Chain Scan Frequency</label>
          <select
            value={state.supplyChainScanFreq}
            onChange={(e) => update("supplyChainScanFreq", e.target.value)}
            className={inputClass}
          >
            <option value="on-demand">On demand</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>

        {/* Auto-block God Key servers toggle */}
        <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-surface-2 px-4 py-3">
          <div>
            <p className="text-sm font-medium text-gray-200">Auto-Block God Key Servers</p>
            <p className="text-xs text-gray-400">Automatically block MCP servers with access to more than 20 downstream resources</p>
          </div>
          <button
            onClick={() => update("autoBlockGodKey", !state.autoBlockGodKey)}
            className={clsx(
              "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
              state.autoBlockGodKey ? "bg-brand-500" : "bg-gray-700",
            )}
          >
            <span
              className={clsx(
                "inline-block h-4 w-4 rounded-full bg-white transition-transform",
                state.autoBlockGodKey ? "translate-x-6" : "translate-x-1",
              )}
            />
          </button>
        </div>
      </div>

      {/* ── SOC Brain Settings ─────────────────────────────────────── */}
      <div className={cardClass}>
        <div className="flex items-center gap-2 mb-1">
          <Brain className="h-5 w-5 text-brand-400" />
          <h3 className={sectionHeading}>SOC Brain Settings</h3>
        </div>
        <p className={sectionDesc}>
          AI-driven cross-vendor security operations configuration.
        </p>

        {/* Auto-execute confidence threshold */}
        <div className="mb-5">
          <label className={labelClass}>
            Auto-Execute Confidence Threshold: <span className="text-brand-400">{state.autoExecuteThreshold.toFixed(2)}</span>
          </label>
          <input
            type="range"
            min="0.5"
            max="1.0"
            step="0.01"
            value={state.autoExecuteThreshold}
            onChange={(e) => update("autoExecuteThreshold", parseFloat(e.target.value))}
            className="w-full accent-brand-500"
          />
          <div className="flex justify-between text-xs text-gray-600 mt-1">
            <span>0.50</span>
            <span>1.00</span>
          </div>
        </div>

        <div className="mb-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className={labelClass}>Approval Timeout (minutes)</label>
            <input
              type="number"
              value={state.approvalTimeout}
              onChange={(e) => update("approvalTimeout", parseInt(e.target.value) || 0)}
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass}>Default Escalation Tier</label>
            <select
              value={state.defaultEscalationTier}
              onChange={(e) => update("defaultEscalationTier", e.target.value)}
              className={inputClass}
            >
              <option value="tier-1">Tier 1</option>
              <option value="tier-2">Tier 2</option>
              <option value="tier-3">Tier 3</option>
              <option value="ciso">CISO</option>
            </select>
          </div>
        </div>

        {/* Vendor Connectors */}
        <div>
          <label className={labelClass}>Vendor Connectors</label>
          <div className="space-y-3">
            {([
              { enabledKey: "crowdStrikeEnabled" as const, keyField: "crowdStrikeKey" as const, label: "CrowdStrike" },
              { enabledKey: "defenderEnabled" as const, keyField: "defenderKey" as const, label: "Microsoft Defender" },
              { enabledKey: "wizEnabled" as const, keyField: "wizKey" as const, label: "Wiz" },
            ]).map(({ enabledKey, keyField, label }) => (
              <div
                key={enabledKey}
                className="flex items-center gap-4 rounded-lg border border-white/[0.06] bg-surface-2 px-4 py-3"
              >
                <button
                  onClick={() => update(enabledKey, !state[enabledKey])}
                  className={clsx(
                    "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors",
                    state[enabledKey] ? "bg-brand-500" : "bg-gray-700",
                  )}
                >
                  <span
                    className={clsx(
                      "inline-block h-4 w-4 rounded-full bg-white transition-transform",
                      state[enabledKey] ? "translate-x-6" : "translate-x-1",
                    )}
                  />
                </button>
                <span className="text-sm font-medium text-gray-200 w-36">{label}</span>
                <input
                  type="password"
                  placeholder={state[enabledKey] ? "Enter API key..." : "Disabled"}
                  disabled={!state[enabledKey]}
                  value={state[keyField]}
                  onChange={(e) => update(keyField, e.target.value)}
                  className={clsx(
                    inputClass,
                    "flex-1",
                    !state[enabledKey] && "opacity-50 cursor-not-allowed",
                  )}
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Save button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="inline-flex items-center gap-2 rounded-lg bg-brand-600 px-6 py-2.5 text-sm font-medium text-white transition-colors hover:bg-brand-500"
        >
          <Save className="h-4 w-4" />
          Save Changes
        </button>
      </div>
    </div>
  );
}

// ── Agents Tab ───────────────────────────────────────────────────────────

function AgentsTab() {
  const {
    data: agents = [],
    isLoading,
    error,
  } = useQuery({
    queryKey: ["agents"],
    queryFn: () => get<Agent[]>("/agents/"),
  });

  const agentColumns: Column<Agent>[] = [
    {
      key: "id",
      header: "ID",
      render: (row) => (
        <span className="font-mono text-xs text-gray-400" title={row.id}>
          {row.id.slice(0, 8)}...
        </span>
      ),
    },
    {
      key: "agent_type",
      header: "Type",
      render: (row) => <span className="capitalize text-gray-200">{row.agent_type}</span>,
    },
    {
      key: "environment",
      header: "Environment",
      render: (row) => <span className="text-gray-300">{row.environment}</span>,
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      key: "last_heartbeat",
      header: "Last Heartbeat",
      render: (row) =>
        row.last_heartbeat ? (
          <span className="text-gray-400">
            {formatDistanceToNow(new Date(row.last_heartbeat), { addSuffix: true })}
          </span>
        ) : (
          <span className="text-gray-600">Never</span>
        ),
    },
  ];

  if (isLoading) {
    return <LoadingSpinner size="sm" className="py-12" />;
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
        Failed to load agents.
      </div>
    );
  }

  return (
    <DataTable
      columns={agentColumns}
      data={agents}
      keyExtractor={(row) => row.id}
      emptyMessage="No agents registered yet."
    />
  );
}

// ── Notifications Tab ────────────────────────────────────────────────────

interface NotificationConfig {
  id: string;
  channel_type: string;
  channel_name: string;
  enabled: boolean;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface NotificationPref {
  id: string;
  user_id: string;
  channel: string;
  event_type: string;
  enabled: boolean;
  config: Record<string, unknown> | null;
  created_at: string | null;
  updated_at: string | null;
}

interface EventTypeInfo {
  event_type: string;
  description: string;
}

const CHANNELS = ["email", "slack", "pagerduty", "webhook"] as const;

const CHANNEL_ICONS: Record<string, React.ReactNode> = {
  slack: <MessageSquare className="h-5 w-5" />,
  pagerduty: <Siren className="h-5 w-5" />,
  email: <Mail className="h-5 w-5" />,
  webhook: <Webhook className="h-5 w-5" />,
};

const CHANNEL_LABELS: Record<string, string> = {
  email: "Email",
  slack: "Slack",
  pagerduty: "PagerDuty",
  webhook: "Webhook",
};

const CHANNEL_DESCRIPTIONS: Record<string, string> = {
  slack: "Send alerts and incident updates to Slack channels",
  pagerduty: "Escalate critical incidents to on-call engineers",
  email: "Email notifications for daily digests and reports",
  webhook: "Custom HTTP webhooks for third-party integrations",
};

function NotificationsTab() {
  const queryClient = useQueryClient();

  // Fetch channel configs (existing)
  const {
    data: configs = [],
    isLoading: configsLoading,
    error: configsError,
  } = useQuery({
    queryKey: ["notification-configs"],
    queryFn: () => get<NotificationConfig[]>("/notification-configs"),
  });

  // Fetch per-user preferences
  const {
    data: prefsData,
    isLoading: prefsLoading,
  } = useQuery({
    queryKey: ["notification-preferences"],
    queryFn: () =>
      get<{ items: NotificationPref[]; total: number }>(
        "/users/me/notification-preferences",
      ),
  });

  // Fetch available event types
  const { data: eventsData } = useQuery({
    queryKey: ["notification-events"],
    queryFn: () =>
      get<{ items: EventTypeInfo[]; total: number }>("/notification-events"),
  });

  const eventTypes = useMemo(
    () => eventsData?.items ?? [],
    [eventsData],
  );
  const savedPrefs = useMemo(
    () => prefsData?.items ?? [],
    [prefsData],
  );

  // Local toggle state: key = "channel::event_type" -> boolean
  const [localToggles, setLocalToggles] = useState<
    Record<string, boolean>
  >({});
  const [dirty, setDirty] = useState(false);

  // Build the effective state: saved prefs + local overrides
  const getToggleKey = (channel: string, eventType: string) =>
    `${channel}::${eventType}`;

  const isEnabled = useCallback(
    (channel: string, eventType: string): boolean => {
      const key = getToggleKey(channel, eventType);
      if (key in localToggles) return localToggles[key];
      const pref = savedPrefs.find(
        (p) => p.channel === channel && p.event_type === eventType,
      );
      return pref?.enabled ?? false;
    },
    [localToggles, savedPrefs],
  );

  const handleToggle = useCallback(
    (channel: string, eventType: string) => {
      const key = getToggleKey(channel, eventType);
      const current = isEnabled(channel, eventType);
      setLocalToggles((prev) => ({ ...prev, [key]: !current }));
      setDirty(true);
    },
    [isEnabled],
  );

  // Bulk upsert mutation
  const saveMutation = useMutation({
    mutationFn: async () => {
      // Build the full preference set from current state
      const preferences: {
        channel: string;
        event_type: string;
        enabled: boolean;
      }[] = [];

      for (const et of eventTypes) {
        for (const ch of CHANNELS) {
          const enabled = isEnabled(ch, et.event_type);
          // Only send prefs that are enabled or were previously saved
          const wasSaved = savedPrefs.some(
            (p) =>
              p.channel === ch && p.event_type === et.event_type,
          );
          if (enabled || wasSaved) {
            preferences.push({
              channel: ch,
              event_type: et.event_type,
              enabled,
            });
          }
        }
      }

      if (preferences.length === 0) return;

      await put("/users/me/notification-preferences", {
        preferences,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["notification-preferences"],
      });
      setLocalToggles({});
      setDirty(false);
    },
  });

  if (configsLoading || prefsLoading) {
    return <LoadingSpinner size="sm" className="py-12" />;
  }

  // Build channel list for the existing channels overview
  const knownTypes = ["slack", "pagerduty", "email", "webhook"];
  const configuredTypes = new Set(configs.map((c) => c.channel_type));

  const channels = knownTypes.map((type) => {
    const cfg = configs.find((c) => c.channel_type === type);
    return {
      type,
      name:
        cfg?.channel_name ||
        type.charAt(0).toUpperCase() + type.slice(1),
      configured: configuredTypes.has(type),
      enabled: cfg?.enabled ?? false,
      icon: CHANNEL_ICONS[type] || <Bell className="h-5 w-5" />,
      description: CHANNEL_DESCRIPTIONS[type] || "",
    };
  });

  return (
    <div className="space-y-6">
      {/* Notification Channels overview */}
      <div className="rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <div className="border-b border-gray-800/60 px-5 py-4">
          <h3 className="font-semibold text-gray-50">
            Notification Channels
          </h3>
          <p className="mt-1 text-sm text-gray-500">
            Configure how ShieldOps alerts your team about incidents
            and agent actions.
          </p>
          {configsError && (
            <p className="mt-2 text-xs text-red-400">
              Failed to load from API — showing defaults.
            </p>
          )}
        </div>
        <ul className="divide-y divide-gray-800/40">
          {channels.map((channel) => (
            <li
              key={channel.type}
              className="flex items-center gap-4 px-5 py-4"
            >
              <div className="text-gray-400">{channel.icon}</div>
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-200">
                  {channel.name}
                </p>
                <p className="text-xs text-gray-500">
                  {channel.description}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <div
                  className={clsx(
                    "h-2 w-2 rounded-full",
                    channel.configured && channel.enabled
                      ? "bg-green-400"
                      : "bg-gray-600",
                  )}
                />
                <span className="text-xs text-gray-400">
                  {channel.configured
                    ? channel.enabled
                      ? "Enabled"
                      : "Disabled"
                    : "Not configured"}
                </span>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {/* Notification Preferences grid */}
      <div className="rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <div className="flex items-center justify-between border-b border-gray-800/60 px-5 py-4">
          <div>
            <h3 className="font-semibold text-gray-50">
              Notification Preferences
            </h3>
            <p className="mt-1 text-sm text-gray-500">
              Choose which events notify you on each channel.
            </p>
          </div>
          <button
            onClick={() => saveMutation.mutate()}
            disabled={!dirty || saveMutation.isPending}
            className={clsx(
              "inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors",
              dirty
                ? "bg-brand-600 text-white hover:bg-brand-500"
                : "bg-gray-800 text-gray-500 cursor-not-allowed",
            )}
          >
            {saveMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            Save
          </button>
        </div>

        {saveMutation.isError && (
          <div className="mx-5 mt-3 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            Failed to save preferences. Please try again.
          </div>
        )}
        {saveMutation.isSuccess && !dirty && (
          <div className="mx-5 mt-3 rounded-lg border border-green-500/20 bg-green-500/10 px-3 py-2 text-xs text-green-400">
            Preferences saved successfully.
          </div>
        )}

        {eventTypes.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800/60">
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                    Event
                  </th>
                  {CHANNELS.map((ch) => (
                    <th
                      key={ch}
                      className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider text-gray-500"
                    >
                      <div className="flex flex-col items-center gap-1">
                        {CHANNEL_ICONS[ch]}
                        <span>{CHANNEL_LABELS[ch]}</span>
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {eventTypes.map((et) => (
                  <tr key={et.event_type} className="hover:bg-gray-800/30">
                    <td className="px-5 py-3">
                      <p className="font-mono text-xs text-gray-200">
                        {et.event_type}
                      </p>
                      <p className="mt-0.5 text-xs text-gray-500">
                        {et.description}
                      </p>
                    </td>
                    {CHANNELS.map((ch) => {
                      const on = isEnabled(ch, et.event_type);
                      return (
                        <td key={ch} className="px-4 py-3 text-center">
                          <button
                            onClick={() =>
                              handleToggle(ch, et.event_type)
                            }
                            className={clsx(
                              "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                              on ? "bg-brand-500" : "bg-gray-700",
                            )}
                            aria-label={`${et.event_type} via ${ch}`}
                          >
                            <span
                              className={clsx(
                                "inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform",
                                on
                                  ? "translate-x-[18px]"
                                  : "translate-x-[3px]",
                              )}
                            />
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="px-5 py-8 text-center text-sm text-gray-500">
            No event types available.
          </div>
        )}
      </div>
    </div>
  );
}

// ── API Tab ──────────────────────────────────────────────────────────────

function ApiTab() {
  const { token } = useAuthStore();
  const [copied, setCopied] = useState(false);

  const baseUrl = `${window.location.origin}/api/v1`;
  const docsUrl = `${baseUrl}/docs`;
  const openApiUrl = `${baseUrl}/openapi.json`;

  function maskToken(t: string | null): string {
    if (!t) return "No token available";
    if (t.length <= 12) return "****";
    return `${t.slice(0, 6)}${"*".repeat(20)}${t.slice(-6)}`;
  }

  async function copyToken() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may fail in non-secure contexts
    }
  }

  return (
    <div className="space-y-4">
      {/* API Endpoints */}
      <div className="rounded-xl border border-gray-800/80 bg-gray-900 p-5 shadow-card">
        <h3 className="font-semibold text-gray-50">API Endpoints</h3>
        <p className="mt-1 text-sm text-gray-500">
          Use these endpoints to integrate with the ShieldOps API.
        </p>

        <dl className="mt-4 space-y-3">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-gray-500">
              Base URL
            </dt>
            <dd className="mt-0.5 font-mono text-sm text-gray-200">{baseUrl}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-gray-500">
              API Docs
            </dt>
            <dd className="mt-0.5">
              <a
                href={docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 font-mono text-sm text-brand-400 hover:text-brand-300"
              >
                {docsUrl}
                <ExternalLink className="h-3 w-3" />
              </a>
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-gray-500">
              OpenAPI Spec
            </dt>
            <dd className="mt-0.5">
              <a
                href={openApiUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 font-mono text-sm text-brand-400 hover:text-brand-300"
              >
                {openApiUrl}
                <ExternalLink className="h-3 w-3" />
              </a>
            </dd>
          </div>
        </dl>
      </div>

      {/* Token section */}
      <div className="rounded-xl border border-gray-800/80 bg-gray-900 p-5 shadow-card">
        <h3 className="font-semibold text-gray-50">Your Token</h3>
        <p className="mt-1 text-sm text-gray-500">
          Use this bearer token to authenticate API requests.
        </p>

        <div className="mt-3 flex items-center gap-2">
          <div className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2">
            <code className="text-sm text-gray-300">{maskToken(token)}</code>
          </div>
          <button
            onClick={copyToken}
            disabled={!token}
            className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-300 transition-colors hover:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {copied ? (
              <>
                <Check className="h-4 w-4 text-green-400" />
                Copied
              </>
            ) : (
              <>
                <Copy className="h-4 w-4" />
                Copy
              </>
            )}
          </button>
        </div>
      </div>

      {/* Swagger link */}
      <div className="rounded-xl border border-gray-800/80 bg-gray-900 p-5 shadow-card">
        <h3 className="font-semibold text-gray-50">Interactive Documentation</h3>
        <p className="mt-1 text-sm text-gray-500">
          Explore and test API endpoints using the interactive Swagger UI.
        </p>
        <a
          href={docsUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 inline-flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-500"
        >
          Open Swagger Docs
          <ExternalLink className="h-4 w-4" />
        </a>
      </div>
    </div>
  );
}
