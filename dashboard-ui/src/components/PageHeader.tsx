import clsx from "clsx";
import { Loader2 } from "lucide-react";

const BADGE_VARIANTS = {
  info: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15",
  success: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15",
  warning: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
  error: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
} as const;

interface PageHeaderProps {
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
    icon?: React.ReactNode;
    loading?: boolean;
  };
  badge?: {
    label: string;
    variant: keyof typeof BADGE_VARIANTS;
  };
}

export default function PageHeader({ title, description, action, badge }: PageHeaderProps) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold tracking-tight text-gray-50 sm:text-2xl">{title}</h1>
          {badge && (
            <span
              className={clsx(
                "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset",
                BADGE_VARIANTS[badge.variant],
              )}
            >
              {badge.label}
            </span>
          )}
        </div>
        {description && (
          <p className="mt-1 text-[13px] text-gray-600">{description}</p>
        )}
      </div>

      {action && (
        <button
          onClick={action.onClick}
          disabled={action.loading}
          className={clsx(
            "btn-secondary mt-3 sm:mt-0",
            action.loading && "cursor-not-allowed opacity-60",
          )}
        >
          {action.loading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            action.icon
          )}
          {action.label}
        </button>
      )}
    </div>
  );
}
