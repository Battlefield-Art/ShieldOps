import clsx from "clsx";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

interface MetricCardProps {
  label?: string;
  /** @deprecated use `label` */
  title?: string;
  value: string | number;
  change?: number;
  icon?: React.ReactNode;
  description?: string;
  /** @deprecated use `description` */
  subtitle?: string;
}

export default function MetricCard({
  label,
  title,
  value,
  change,
  icon,
  description,
  subtitle,
}: MetricCardProps) {
  const resolvedLabel = label ?? title ?? "";
  const resolvedDescription = description ?? subtitle;
  const trend =
    change === undefined || change === 0
      ? "neutral"
      : change > 0
        ? "up"
        : "down";

  return (
    <div
      className={clsx(
        "group relative overflow-hidden rounded-xl border p-5 transition-all duration-200",
        "bg-surface-2 shadow-depth hover-lift",
        trend === "up" && "border-white/[0.06] hover:border-emerald-500/20",
        trend === "down" && "border-white/[0.06] hover:border-red-500/20",
        trend === "neutral" && "border-white/[0.06] hover:border-white/[0.1]",
      )}
    >
      {/* Subtle top accent line */}
      <div
        className={clsx(
          "absolute inset-x-0 top-0 h-px",
          trend === "up" && "bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent",
          trend === "down" && "bg-gradient-to-r from-transparent via-red-500/30 to-transparent",
          trend === "neutral" && "bg-gradient-to-r from-transparent via-white/[0.06] to-transparent",
        )}
      />

      <div className="flex items-start justify-between">
        <p className="text-[13px] font-medium text-gray-500">{resolvedLabel}</p>
        {icon && (
          <div className="rounded-lg bg-white/[0.03] p-1.5 text-gray-600 transition-colors duration-200 group-hover:text-gray-500">
            {icon}
          </div>
        )}
      </div>

      <p className="metric-value mt-2.5 text-[28px] font-semibold leading-none tracking-tight text-gray-50">
        {value}
      </p>

      {resolvedDescription && (
        <p className="mt-1.5 text-xs text-gray-600">{resolvedDescription}</p>
      )}

      {change !== undefined && (
        <div className="mt-3 flex items-center gap-1.5">
          <div
            className={clsx(
              "flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium",
              trend === "up" && "bg-emerald-500/[0.08] text-emerald-400",
              trend === "down" && "bg-red-500/[0.08] text-red-400",
              trend === "neutral" && "bg-white/[0.04] text-gray-500",
            )}
          >
            {trend === "up" && <TrendingUp className="h-3 w-3" />}
            {trend === "down" && <TrendingDown className="h-3 w-3" />}
            {trend === "neutral" && <Minus className="h-3 w-3" />}
            {change > 0 ? "+" : ""}
            {change.toFixed(1)}%
          </div>
        </div>
      )}
    </div>
  );
}
