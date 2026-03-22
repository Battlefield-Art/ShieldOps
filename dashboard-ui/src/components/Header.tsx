import { useState, useEffect, useCallback } from "react";
import { LogOut, Menu, Search, Command } from "lucide-react";
import clsx from "clsx";
import { useAuthStore } from "../store/auth";
import ConnectionStatus from "./ConnectionStatus";
import GlobalSearch from "./GlobalSearch";
import NotificationDropdown from "./NotificationDropdown";

interface HeaderProps {
  onMenuClick?: () => void;
}

export default function Header({ onMenuClick }: HeaderProps) {
  const { user, logout } = useAuthStore();
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  const openSearch = useCallback(() => setIsSearchOpen(true), []);
  const closeSearch = useCallback(() => setIsSearchOpen(false), []);

  // Global keyboard shortcut: Cmd+K (Mac) / Ctrl+K (Windows)
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Detect scroll to add bottom shadow
  useEffect(() => {
    const container = document.querySelector("main");
    if (!container) return;

    function onScroll() {
      setScrolled((container as HTMLElement).scrollTop > 0);
    }

    container.addEventListener("scroll", onScroll, { passive: true });
    return () => container.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <>
      <header
        className={clsx(
          "flex h-14 shrink-0 items-center justify-between border-b px-4 transition-all duration-200 sm:px-5",
          scrolled
            ? "border-white/[0.06] bg-surface-1/90 shadow-lg shadow-black/10 backdrop-blur-xl"
            : "border-white/[0.04] bg-surface-1/60 backdrop-blur-sm",
        )}
      >
        <div className="flex items-center gap-3">
          {/* Mobile hamburger */}
          {onMenuClick && (
            <button
              onClick={onMenuClick}
              className="rounded-lg p-1.5 text-gray-500 transition-colors duration-150 hover:bg-white/[0.04] hover:text-gray-300 lg:hidden focus-ring"
              aria-label="Open menu"
            >
              <Menu className="h-5 w-5" />
            </button>
          )}

          {/* Search trigger */}
          <button
            onClick={openSearch}
            className={clsx(
              "flex items-center gap-2.5 rounded-lg border px-3 py-1.5 text-sm transition-all duration-200 focus-ring",
              "border-white/[0.06] bg-white/[0.02] text-gray-500",
              "hover:border-white/[0.1] hover:bg-white/[0.04] hover:text-gray-400",
              "sm:w-72 lg:w-80",
            )}
          >
            <Search className="h-3.5 w-3.5 shrink-0" />
            <span className="hidden sm:inline">Search commands, pages...</span>
            <kbd className="ml-auto hidden items-center gap-0.5 rounded border border-white/[0.06] bg-white/[0.03] px-1.5 py-0.5 font-mono text-[10px] text-gray-600 sm:inline-flex">
              <Command className="h-2.5 w-2.5" />K
            </kbd>
          </button>
        </div>

        <div className="flex items-center gap-1 sm:gap-2">
          {/* WebSocket connection status */}
          <ConnectionStatus />

          {/* Notifications */}
          <NotificationDropdown />

          {/* Divider */}
          {user && <div className="mx-1.5 hidden h-5 w-px bg-white/[0.06] sm:block" />}

          {/* User */}
          {user && (
            <div className="flex items-center gap-2.5">
              {/* Avatar */}
              <div className="flex h-7 w-7 items-center justify-center rounded-full text-xs font-semibold text-brand-300 ring-1 ring-brand-500/20"
                style={{ background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.15), rgba(6, 182, 212, 0.05))' }}
              >
                {user.name?.charAt(0)?.toUpperCase() ?? "U"}
              </div>
              <div className="hidden text-right sm:block">
                <p className="text-[13px] font-medium leading-none text-gray-200">{user.name}</p>
                <p className="mt-0.5 text-[11px] text-gray-600">{user.role}</p>
              </div>
              <button
                onClick={logout}
                className="rounded-lg p-1.5 text-gray-600 transition-colors duration-150 hover:bg-white/[0.04] hover:text-red-400 focus-ring"
                aria-label="Sign out"
                title="Sign out"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Global search modal */}
      <GlobalSearch isOpen={isSearchOpen} onClose={closeSearch} />
    </>
  );
}
