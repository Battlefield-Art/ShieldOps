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
        maxHeight: isExpanded ? `${(items.length * 40) + 4}px` : "0px",
        opacity: isExpanded ? 1 : 0,
      }}
    >
      <div ref={contentRef} className="mt-0.5 space-y-0.5">
        {items.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/app"}
            className={({ isActive }) =>
              clsx(
                "group/item flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] font-medium transition-all duration-150",
                "focus:outline-none focus:ring-2 focus:ring-brand-500/40",
                collapsed && "justify-center px-2",
                isActive
                  ? "bg-brand-500/10 text-brand-400 shadow-sm shadow-brand-500/5"
                  : "text-gray-400 hover:bg-gray-800/70 hover:text-gray-200",
              )
            }
            title={collapsed ? label : undefined}
          >
            <Icon className={clsx(
              "h-4 w-4 shrink-0 transition-colors duration-150",
            )} />
            {!collapsed && <span className="truncate">{label}</span>}
            {/* Active indicator bar */}
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
        "flex h-full flex-col border-r border-gray-800/60 bg-gray-900/95 transition-all duration-200",
        collapsed ? "w-16" : "w-60",
      )}
    >
      {/* Logo */}
      <div className="flex items-center justify-between border-b border-gray-800/40 px-4 py-5">
        <Logo size={collapsed ? "sm" : "md"} showText={!collapsed} />
        <button
          onClick={toggleCollapsed}
          className="rounded-lg p-1.5 text-gray-500 transition-colors duration-150 hover:bg-gray-800 hover:text-gray-300 focus:outline-none focus:ring-2 focus:ring-brand-500/40"
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
                <div className="mx-3 my-1.5 border-t border-gray-800/30" />
              )}
              <div className="mb-0.5">
                {/* Group header */}
                <button
                  onClick={() => toggleGroup(group.id)}
                  className={clsx(
                    "flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-[11px] font-semibold uppercase tracking-wider transition-colors duration-150",
                    "focus:outline-none focus:ring-2 focus:ring-brand-500/40",
                    isGroupActive
                      ? `${group.color}`
                      : "text-gray-500 hover:text-gray-400",
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
      <div className="border-t border-gray-800/40 px-4 py-3">
        {!collapsed && (
          <p className="text-[11px] text-gray-600">ShieldOps v0.1.0</p>
        )}
      </div>
    </aside>
  );
}
