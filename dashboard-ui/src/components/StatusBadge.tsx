import clsx from "clsx";

const VARIANT_CLASSES: Record<string, string> = {
  success: "bg-green-500/10 text-green-400 ring-green-500/20",
  warning: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  error: "bg-red-500/10 text-red-400 ring-red-500/20",
  info: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  cyan: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
  neutral: "bg-gray-500/10 text-gray-400 ring-gray-500/20",
};

// Map common statuses to variants
const STATUS_MAP: Record<string, string> = {
  // Green
  healthy: "success",
  running: "success",
  active: "success",
  success: "success",
  resolved: "success",
  compliant: "success",
  low: "success",
  // Amber
  warning: "warning",
  degraded: "warning",
  partial: "warning",
  tuning: "warning",
  in_progress: "warning",
  pending_approval: "warning",
  executing: "warning",
  medium: "warning",
  // Red
  error: "error",
  failed: "error",
  critical: "error",
  stopped: "error",
  non_compliant: "error",
  rolled_back: "error",
  high: "error",
  // Gray
  pending: "neutral",
  draft: "neutral",
  planned: "neutral",
  unknown: "neutral",
  offline: "neutral",
  idle: "neutral",
  // Cyan
  completed: "cyan",
  applied: "cyan",
  deployed: "cyan",
  approved: "cyan",
};

// Statuses that show an animated dot
const ANIMATED_STATUSES = new Set(["running", "active", "executing", "in_progress"]);

interface StatusBadgeProps {
  status: string;
  size?: "sm" | "md";
  variant?: keyof typeof VARIANT_CLASSES;
}

export default function StatusBadge({ status, size = "sm", variant }: StatusBadgeProps) {
  const v = variant ?? STATUS_MAP[status.toLowerCase()] ?? "neutral";
  const showDot = ANIMATED_STATUSES.has(status.toLowerCase());

  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-md font-medium ring-1 ring-inset",
        size === "sm" && "px-2 py-0.5 text-[11px]",
        size === "md" && "px-2.5 py-1 text-xs",
        VARIANT_CLASSES[v],
      )}
    >
      {showDot && (
        <span className="relative flex h-1.5 w-1.5">
          <span
            className={clsx(
              "absolute inline-flex h-full w-full animate-ping rounded-full opacity-60",
              v === "success" && "bg-green-400",
              v === "warning" && "bg-amber-400",
              v === "error" && "bg-red-400",
            )}
          />
          <span
            className={clsx(
              "relative inline-flex h-1.5 w-1.5 rounded-full",
              v === "success" && "bg-green-400",
              v === "warning" && "bg-amber-400",
              v === "error" && "bg-red-400",
            )}
          />
        </span>
      )}
      {status.replace(/_/g, " ")}
    </span>
  );
}
