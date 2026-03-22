import { TrendingDown, Clock, Zap, ArrowDown } from "lucide-react";
import clsx from "clsx";

interface Metric {
  label: string;
  value: string;
  change: string;
  improved: boolean;
  icon: typeof Clock;
}

const METRICS: Metric[] = [
  {
    label: "MTTD",
    value: "2.3m",
    change: "-67%",
    improved: true,
    icon: Clock,
  },
  {
    label: "MTTA",
    value: "45s",
    change: "-84%",
    improved: true,
    icon: Zap,
  },
  {
    label: "MTTR",
    value: "8.1m",
    change: "-73%",
    improved: true,
    icon: TrendingDown,
  },
];

interface MetricsBarProps {
  className?: string;
}

export default function MetricsBar({ className }: MetricsBarProps) {
  return (
    <div className={clsx("flex items-center gap-5", className)}>
      {METRICS.map((metric) => (
        <div key={metric.label} className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-white/[0.03]">
            <metric.icon className="h-3.5 w-3.5 text-gray-600" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="metric-value text-[13px] font-bold text-gray-200">{metric.value}</span>
              <span
                className={clsx(
                  "inline-flex items-center gap-0.5 text-[11px] font-medium",
                  metric.improved ? "text-emerald-400" : "text-red-400",
                )}
              >
                <ArrowDown className="h-2.5 w-2.5" />
                {metric.change}
              </span>
            </div>
            <p className="text-[10px] font-medium text-gray-700 uppercase tracking-[0.08em]">
              {metric.label}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
