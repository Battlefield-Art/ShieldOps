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
        trend === "up" && "border-l-green-500/60 border-t-gray-800 border-r-gray-800 border-b-gray-800 border-l-2",
        trend === "down" && "border-l-red-500/60 border-t-gray-800 border-r-gray-800 border-b-gray-800 border-l-2",
        trend === "neutral" && "border-gray-800",
        "hover:border-gray-700 hover:shadow-lg hover:shadow-gray-900/50",
      )}
    >
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-400">{label}</p>
        {icon && (
          <div className="text-gray-500 transition-colors duration-200 group-hover:text-gray-400">
            {icon}
          </div>
        )}
      </div>

      <p className="mt-2 text-3xl font-semibold tracking-tight text-gray-50">{value}</p>

      {description && (
        <p className="mt-1 text-xs text-gray-500">{description}</p>
      )}

      {change !== undefined && (
        <div
          className={clsx(
            "mt-2 flex items-center gap-1 text-xs font-medium",
            trend === "up" && "text-green-400",
            trend === "down" && "text-red-400",
            trend === "neutral" && "text-gray-500",
          )}
        >
          {trend === "up" && <TrendingUp className="h-3 w-3" />}
          {trend === "down" && <TrendingDown className="h-3 w-3" />}
          {trend === "neutral" && <Minus className="h-3 w-3" />}
          {change > 0 ? "+" : ""}
          {change.toFixed(1)}%
        </div>
      )}

      {/* Sparkline-style trend bar */}
      {change !== undefined && trend !== "neutral" && (
        <div className="absolute bottom-0 left-0 right-0 h-0.5">
          <div
            className={clsx(
              "h-full transition-all duration-500",
              trend === "up" && "bg-gradient-to-r from-green-500/0 via-green-500/40 to-green-500/0",
              trend === "down" && "bg-gradient-to-r from-red-500/0 via-red-500/40 to-red-500/0",
            )}
            style={{ width: `${Math.min(Math.abs(change) * 5, 100)}%`, marginLeft: "auto", marginRight: "auto" }}
          />
        </div>
      )}
    </div>
  );
}
