import { NavLink, useLocation } from "react-router-dom";
import { ChevronRight, PanelLeftClose, PanelLeft } from "lucide-react";
import Logo from "./Logo";
import clsx from "clsx";
import { useEffect, useRef } from "react";
import { NAV_GROUPS } from "../config/products";
import { useSidebarStore } from "../store/sidebar";

function GroupItems({
  items,
  collapsed,
  isExpanded,
}: {
  items: typeof NAV_GROUPS[number]["items"];
  collapsed: boolean;
  isExpanded: boolean;
}) {
  const contentRef = useRef<HTMLDivElement>(null);

  return (
    <div
      className="overflow-hidden transition-all duration-200 ease-in-out"
      style={{
        maxHeight: isExpanded ? `${(items.length * 38) + 4}px` : "0px",
        opacity: isExpanded ? 1 : 0,
      }}
    >
      <div ref={contentRef} className="mt-0.5 space-y-px">
        {items.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/app"}
            className={({ isActive }) =>
              clsx(
                "group/item flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[13px] font-medium transition-all duration-150",
                "focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40",
                collapsed && "justify-center px-2",
                isActive
                  ? "nav-active-line bg-brand-500/[0.08] text-brand-300"
                  : "text-gray-500 hover:bg-white/[0.03] hover:text-gray-300",
              )
            }
            title={collapsed ? label : undefined}
          >
            <Icon className="h-[15px] w-[15px] shrink-0 transition-colors duration-150" />
            {!collapsed && <span className="truncate">{label}</span>}
          </NavLink>
        ))}
      </div>
    </div>
  );
}

export default function Sidebar() {
  const location = useLocation();
  const { collapsed, expandedGroups, toggleCollapsed, toggleGroup, expandGroup } =
    useSidebarStore();

  // Auto-expand the group containing the active route
  useEffect(() => {
    for (const group of NAV_GROUPS) {
      const isActive = group.items.some(
        (item) =>
          location.pathname === item.to ||
          (item.to !== "/app" && location.pathname.startsWith(item.to)),
      );
      const isAgentRoute =
        group.id === "agent-factory" &&
        (location.pathname.startsWith("/app/agent-task") ||
          location.pathname.startsWith("/app/war-room"));
      if (isActive || isAgentRoute) {
        expandGroup(group.id);
        break;
      }
    }
  }, [location.pathname, expandGroup]);

  return (
    <aside
      className={clsx(
        "flex h-full flex-col border-r border-white/[0.04] bg-surface-1 transition-all duration-200",
        collapsed ? "w-16" : "w-[236px]",
      )}
    >
      {/* Logo */}
      <div className="flex items-center justify-between border-b border-white/[0.04] px-4 py-4">
        <Logo size={collapsed ? "sm" : "md"} showText={!collapsed} />
        <button
          onClick={toggleCollapsed}
          className="rounded-md p-1 text-gray-600 transition-colors duration-150 hover:bg-white/[0.04] hover:text-gray-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40"
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <PanelLeft className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav aria-label="Main navigation" className="flex-1 overflow-y-auto px-2 py-2">
        {NAV_GROUPS.map((group, groupIdx) => {
          const isExpanded = expandedGroups.has(group.id);
          const isGroupActive = group.items.some(
            (item) =>
              location.pathname === item.to ||
              (item.to !== "/app" && location.pathname.startsWith(item.to)),
          );

          return (
            <div key={group.id}>
              {groupIdx > 0 && (
                <div className="mx-3 my-2 h-px bg-white/[0.04]" />
              )}
              <div className="mb-0.5">
                {/* Group header */}
                <button
                  onClick={() => toggleGroup(group.id)}
                  className={clsx(
                    "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors duration-150",
                    "focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40",
                    isGroupActive
                      ? `${group.color}`
                      : "text-gray-600 hover:text-gray-500",
                  )}
                  aria-expanded={isExpanded}
                  aria-label={`${group.label} section`}
                  title={collapsed ? group.label : undefined}
                >
                  <ChevronRight
                    className={clsx(
                      "h-3 w-3 shrink-0 transition-transform duration-200",
                      isExpanded && "rotate-90",
                    )}
                  />
                  {!collapsed && <span className="truncate">{group.label}</span>}
                </button>

                {/* Group items with animated expand/collapse */}
                <GroupItems
                  items={group.items}
                  collapsed={collapsed}
                  isExpanded={isExpanded}
                />
              </div>
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-white/[0.04] px-4 py-3">
        {!collapsed && (
          <p className="text-[10px] font-medium text-gray-700">ShieldOps v0.1.0</p>
        )}
      </div>
    </aside>
  );
}
