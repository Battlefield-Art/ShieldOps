import clsx from "clsx";

interface EmptyStateProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export default function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-xl border border-gray-800 bg-gray-900 text-gray-500">
        {icon}
      </div>
      <h3 className="text-base font-semibold text-gray-200">{title}</h3>
      <p className="mt-1 max-w-sm text-sm text-gray-500">{description}</p>
      {action && (
        <button
          onClick={action.onClick}
          className={clsx(
            "mt-5 inline-flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm font-medium text-gray-200 transition-all duration-150",
            "hover:border-gray-600 hover:bg-gray-750 hover:text-white",
            "focus-ring",
          )}
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
