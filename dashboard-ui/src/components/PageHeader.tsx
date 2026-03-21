import clsx from "clsx";
import { Loader2 } from "lucide-react";

const BADGE_VARIANTS = {
  info: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  success: "bg-green-500/10 text-green-400 ring-green-500/20",
  warning: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  error: "bg-red-500/10 text-red-400 ring-red-500/20",
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
          <h1 className="text-2xl font-bold tracking-tight text-gray-50">{title}</h1>
          {badge && (
            <span
              className={clsx(
                "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset",
                BADGE_VARIANTS[badge.variant],
              )}
            >
              {badge.label}
            </span>
          )}
        </div>
        {description && (
          <p className="mt-1.5 text-sm text-gray-500">{description}</p>
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
