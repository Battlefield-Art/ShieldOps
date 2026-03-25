
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
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-white/[0.04] bg-surface-2 text-gray-500 shadow-card">
        {icon}
      </div>
      <h3 className="text-base font-semibold text-gray-200">{title}</h3>
      <p className="mt-1.5 max-w-sm text-sm text-gray-500">{description}</p>
      {action && (
        <button
          onClick={action.onClick}
          className="btn-secondary mt-5"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
