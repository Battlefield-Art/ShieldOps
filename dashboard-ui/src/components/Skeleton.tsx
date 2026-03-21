import clsx from "clsx";

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={clsx(
        "animate-pulse rounded-lg bg-gray-800/60",
        className,
      )}
    />
  );
}

export function MetricCardSkeleton() {
  return (
    <div className="rounded-xl border border-gray-800/80 bg-gray-900 p-6 shadow-card">
      <Skeleton className="mb-3 h-4 w-24" />
      <Skeleton className="mb-2 h-8 w-16" />
      <Skeleton className="h-3 w-32" />
    </div>
  );
}

export function TableRowSkeleton({ columns = 4 }: { columns?: number }) {
  return (
    <tr className="border-b border-gray-800/40">
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="px-5 py-3.5">
          <Skeleton className="h-4 w-full max-w-[120px]" />
        </td>
      ))}
    </tr>
  );
}
