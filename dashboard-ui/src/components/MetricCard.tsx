import clsx from "clsx";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

interface MetricCardProps {
  label: string;
  value: string | number;
  change?: number;
  icon?: React.ReactNode;
  description?: string;
}

export default function MetricCard({ label, value, change, icon, description }: MetricCardProps) {
  const trend =
    change === undefined || change === 0
      ? "neutral"
      : change > 0
        ? "up"
        : "down";

  return (
    <div
      className={clsx(
        "group relative overflow-hidden rounded-xl border bg-gray-900 p-5 transition-all duration-200",
        "shadow-card hover:shadow-card-hover",
        trend === "up" && "border-gray-800/80 hover:border-green-500/30",
        trend === "down" && "border-gray-800/80 hover:border-red-500/30",
        trend === "neutral" && "border-gray-800/80 hover:border-gray-700",
      )}
    >
      {/* Subtle top gradient accent */}
      <div
        className={clsx(
          "absolute inset-x-0 top-0 h-px",
          trend === "up" && "bg-gradient-to-r from-transparent via-green-500/40 to-transparent",
          trend === "down" && "bg-gradient-to-r from-transparent via-red-500/40 to-transparent",
          trend === "neutral" && "bg-gradient-to-r from-transparent via-gray-700/40 to-transparent",
        )}
      />

      <div className="flex items-start justify-between">
        <p className="text-[13px] font-medium text-gray-400">{label}</p>
        {icon && (
          <div className="rounded-lg bg-gray-800/60 p-2 text-gray-500 transition-colors duration-200 group-hover:text-gray-400">
            {icon}
          </div>
        )}
      </div>

      <p className="metric-value mt-3 text-3xl font-semibold tracking-tight text-gray-50">{value}</p>

      {description && (
        <p className="mt-1 text-xs text-gray-500">{description}</p>
      )}

      {change !== undefined && (
        <div className="mt-3 flex items-center gap-1.5">
          <div
            className={clsx(
              "flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium",
              trend === "up" && "bg-green-500/10 text-green-400",
              trend === "down" && "bg-red-500/10 text-red-400",
              trend === "neutral" && "bg-gray-500/10 text-gray-500",
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
