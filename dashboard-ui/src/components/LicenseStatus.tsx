import { useEffect, useState } from "react";
import clsx from "clsx";
import { ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";

type LicenseStatusValue =
  | "active"
  | "expiring_soon"
  | "grace"
  | "expired"
  | "invalid";

interface LicensePayload {
  org_id: string;
  tier: string;
  agent_limit: number;
  issued_at: string;
  expires_at: string;
}

interface LicenseStatusResponse {
  license: LicensePayload | null;
  status: LicenseStatusValue;
  agents_used: number;
  agents_limit: number;
  days_until_expiry: number | null;
}

interface LicenseStatusProps {
  apiBase?: string;
  authToken?: string;
  pollIntervalMs?: number;
}

const STATUS_META: Record<
  LicenseStatusValue,
  { label: string; color: string; border: string; icon: React.ReactNode }
> = {
  active: {
    label: "Active",
    color: "text-emerald-400",
    border: "border-emerald-500/30",
    icon: <ShieldCheck className="h-5 w-5" />,
  },
  expiring_soon: {
    label: "Expiring Soon",
    color: "text-amber-400",
    border: "border-amber-500/30",
    icon: <ShieldAlert className="h-5 w-5" />,
  },
  grace: {
    label: "Grace Period",
    color: "text-amber-400",
    border: "border-amber-500/40",
    icon: <ShieldAlert className="h-5 w-5" />,
  },
  expired: {
    label: "Expired",
    color: "text-red-400",
    border: "border-red-500/40",
    icon: <ShieldX className="h-5 w-5" />,
  },
  invalid: {
    label: "Invalid / Missing",
    color: "text-red-400",
    border: "border-red-500/40",
    icon: <ShieldX className="h-5 w-5" />,
  },
};

export default function LicenseStatus({
  apiBase = "/api/v1",
  authToken,
  pollIntervalMs = 60_000,
}: LicenseStatusProps) {
  const [data, setData] = useState<LicenseStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const fetchStatus = async () => {
      try {
        const resp = await fetch(`${apiBase}/licenses/current`, {
          headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
        });
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        const json: LicenseStatusResponse = await resp.json();
        if (!cancelled) {
          setData(json);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void fetchStatus();
    const timer = window.setInterval(fetchStatus, pollIntervalMs);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [apiBase, authToken, pollIntervalMs]);

  if (loading) {
    return (
      <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-4 text-sm text-white/60">
        Loading license status…
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-surface-2 p-4 text-sm text-red-400">
        License status unavailable: {error}
      </div>
    );
  }
  if (!data) return null;

  const meta = STATUS_META[data.status];
  const isUnlimited = data.agents_limit < 0;
  const usagePct = isUnlimited
    ? 0
    : data.agents_limit > 0
      ? Math.min(100, (data.agents_used / data.agents_limit) * 100)
      : 0;
  const barColor =
    usagePct > 90
      ? "bg-red-500"
      : usagePct > 75
        ? "bg-amber-500"
        : "bg-emerald-500";

  return (
    <div
      className={clsx(
        "rounded-xl border bg-surface-2 p-5 shadow-depth",
        meta.border,
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-white/50">
            <span>License</span>
            <span>·</span>
            <span className="font-mono">{data.license?.tier ?? "—"}</span>
          </div>
          <div className="mt-1 text-2xl font-semibold text-white">
            {isUnlimited
              ? `${data.agents_used} agents`
              : `${data.agents_used} / ${data.agents_limit} agents`}
          </div>
        </div>
        <div className={clsx("flex items-center gap-2", meta.color)}>
          {meta.icon}
          <span className="text-sm font-medium">{meta.label}</span>
        </div>
      </div>

      {!isUnlimited && (
        <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-white/[0.06]">
          <div
            className={clsx("h-full transition-all duration-500", barColor)}
            style={{ width: `${usagePct}%` }}
          />
        </div>
      )}

      <div className="mt-4 flex items-center justify-between text-xs text-white/50">
        <span>
          {data.license?.org_id ? `org: ${data.license.org_id}` : "no license"}
        </span>
        <span>
          {data.days_until_expiry !== null
            ? data.days_until_expiry >= 0
              ? `${data.days_until_expiry} days until expiry`
              : `expired ${Math.abs(data.days_until_expiry)} days ago`
            : ""}
        </span>
      </div>
    </div>
  );
}
