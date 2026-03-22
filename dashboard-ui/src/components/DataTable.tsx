import clsx from "clsx";
import { useMediaQuery } from "../hooks/useMediaQuery";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => React.ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
  keyExtractor: (row: T) => string;
  emptyMessage?: string;
}

export default function DataTable<T>({
  columns,
  data,
  onRowClick,
  keyExtractor,
  emptyMessage = "No data available",
}: DataTableProps<T>) {
  const isMobile = useMediaQuery("(max-width: 767px)");

  if (data.length === 0) {
    return (
      <div className="rounded-xl border border-white/[0.06] bg-surface-2 p-12 text-center">
        <p className="text-sm text-gray-600">{emptyMessage}</p>
      </div>
    );
  }

  // Mobile: stacked cards
  if (isMobile) {
    return (
      <div className="space-y-2">
        {data.map((row) => (
          <div
            key={keyExtractor(row)}
            onClick={() => onRowClick?.(row)}
            className={clsx(
              "rounded-xl border border-white/[0.06] bg-surface-2 p-4",
              onRowClick && "cursor-pointer hover:border-white/[0.1] hover:bg-surface-3 transition-all",
            )}
          >
            {columns.map((col) => (
              <div key={col.key} className="flex items-baseline justify-between py-1.5">
                <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-gray-600">
                  {col.header}
                </span>
                <span className={clsx("text-sm text-gray-200", col.className)}>
                  {col.render(row)}
                </span>
              </div>
            ))}
          </div>
        ))}
      </div>
    );
  }

  // Desktop: premium table
  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.06]">
      <table className="table-premium w-full text-sm">
        <thead>
          <tr className="border-b border-white/[0.04]">
            {columns.map((col) => (
              <th
                key={col.key}
                className={clsx(
                  "bg-surface-2 px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.08em] text-gray-600",
                  col.className,
                )}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.03] bg-surface-1">
          {data.map((row) => (
            <tr
              key={keyExtractor(row)}
              onClick={() => onRowClick?.(row)}
              className={clsx(
                "transition-colors duration-150",
                onRowClick
                  ? "cursor-pointer hover:bg-white/[0.02]"
                  : "hover:bg-white/[0.01]",
              )}
            >
              {columns.map((col) => (
                <td key={col.key} className={clsx("px-5 py-3.5", col.className)}>
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
