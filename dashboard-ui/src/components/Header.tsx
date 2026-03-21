import { useState, useEffect, useCallback } from "react";
import { LogOut, Menu, Search } from "lucide-react";
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
          "flex h-14 items-center justify-between border-b bg-gray-900/80 px-4 backdrop-blur-sm transition-all duration-200 sm:px-6",
          scrolled
            ? "border-gray-800/80 shadow-md shadow-black/20"
            : "border-gray-800/40",
        )}
      >
        <div className="flex items-center gap-3">
          {/* Mobile hamburger */}
          {onMenuClick && (
            <button
              onClick={onMenuClick}
              className="rounded-lg p-1.5 text-gray-400 transition-colors duration-150 hover:bg-gray-800 hover:text-gray-200 lg:hidden focus-ring"
              aria-label="Open menu"
            >
              <Menu className="h-5 w-5" />
            </button>
          )}

          {/* Search trigger */}
          <button
            onClick={openSearch}
            className="flex items-center gap-2.5 rounded-lg border border-gray-800 bg-gray-900/60 px-3 py-1.5 text-sm text-gray-500 transition-all duration-150 hover:border-gray-700 hover:bg-gray-800/80 hover:text-gray-400 focus-ring sm:w-72 lg:w-80"
          >
            <Search className="h-3.5 w-3.5 shrink-0" />
            <span className="hidden sm:inline">Search commands, pages...</span>
            <kbd className="ml-auto hidden rounded border border-gray-700/60 bg-gray-800/80 px-1.5 py-0.5 font-mono text-[10px] text-gray-500 sm:inline">
              {navigator.platform.includes("Mac") ? "\u2318K" : "Ctrl+K"}
            </kbd>
          </button>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-3">
          {/* WebSocket connection status */}
          <ConnectionStatus />

          {/* Notifications */}
          <NotificationDropdown />

          {/* Divider */}
          {user && <div className="mx-1 hidden h-6 w-px bg-gray-800 sm:block" />}

          {/* User */}
          {user && (
            <div className="flex items-center gap-3">
              {/* Avatar */}
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-500/10 text-xs font-semibold text-brand-400 ring-1 ring-brand-500/20">
                {user.name?.charAt(0)?.toUpperCase() ?? "U"}
              </div>
              <div className="hidden text-right sm:block">
                <p className="text-sm font-medium leading-none text-gray-200">{user.name}</p>
                <p className="mt-0.5 text-[11px] text-gray-500">{user.role}</p>
              </div>
              <button
                onClick={logout}
                className="rounded-lg p-1.5 text-gray-500 transition-colors duration-150 hover:bg-gray-800 hover:text-red-400 focus-ring"
                aria-label="Sign out"
                title="Sign out"
              >
                <LogOut className="h-4 w-4" />
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
