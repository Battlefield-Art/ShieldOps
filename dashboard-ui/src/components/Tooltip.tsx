import clsx from "clsx";

interface TooltipProps {
  content: string;
  children: React.ReactNode;
  side?: "top" | "bottom" | "left" | "right";
}

const positionClasses: Record<string, string> = {
  top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
  bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
  left: "right-full top-1/2 -translate-y-1/2 mr-2",
  right: "left-full top-1/2 -translate-y-1/2 ml-2",
};

const arrowClasses: Record<string, string> = {
  top: "top-full left-1/2 -translate-x-1/2 border-t-gray-800 border-x-transparent border-b-transparent",
  bottom:
    "bottom-full left-1/2 -translate-x-1/2 border-b-gray-800 border-x-transparent border-t-transparent",
  left: "left-full top-1/2 -translate-y-1/2 border-l-gray-800 border-y-transparent border-r-transparent",
  right:
    "right-full top-1/2 -translate-y-1/2 border-r-gray-800 border-y-transparent border-l-transparent",
};

export default function Tooltip({ content, children, side = "top" }: TooltipProps) {
  return (
    <span className="group relative inline-flex">
      {children}
      <span
        className={clsx(
          "pointer-events-none absolute z-50 whitespace-nowrap rounded-md bg-gray-800 px-2.5 py-1.5 text-xs font-medium text-gray-100 opacity-0 shadow-lg transition-opacity duration-150 group-hover:opacity-100",
          positionClasses[side],
        )}
      >
        {content}
        <span
          className={clsx("absolute h-0 w-0 border-[4px]", arrowClasses[side])}
          aria-hidden="true"
        />
      </span>
    </span>
  );
}
