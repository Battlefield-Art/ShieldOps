import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { Menu, X } from "lucide-react";
import clsx from "clsx";
import Logo from "../Logo";

const NAV_LINKS = [
  { label: "Features", to: "/features" },
  { label: "Resources", to: "/resources" },
  { label: "Pricing", to: "/pricing" },
];

export default function LandingNav() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const mobileMenuRef = useRef<HTMLDivElement>(null);
  const [menuHeight, setMenuHeight] = useState(0);

  useEffect(() => {
    function handleScroll() {
      setScrolled(window.scrollY > 8);
    }
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  useEffect(() => {
    if (mobileOpen && mobileMenuRef.current) {
      setMenuHeight(mobileMenuRef.current.scrollHeight);
    } else {
      setMenuHeight(0);
    }
  }, [mobileOpen]);

  return (
    <nav
      className={clsx(
        "fixed top-0 z-50 w-full transition-all duration-300",
        scrolled
          ? "border-b border-white/[0.04] bg-surface-0/90 backdrop-blur-xl"
          : "border-b border-transparent bg-transparent",
      )}
    >
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3.5">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2">
          <Logo />
        </Link>

        {/* Desktop center links */}
        <div className="hidden items-center gap-0.5 md:flex">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.to}
              to={link.to}
              className="group relative rounded-lg px-3 py-2 text-[13px] font-medium text-gray-500 transition-colors hover:text-gray-200"
            >
              {link.label}
              <span className="absolute bottom-1.5 left-3 right-3 h-px origin-left scale-x-0 bg-brand-400/50 transition-transform duration-200 group-hover:scale-x-100" />
            </Link>
          ))}
        </div>

        {/* Desktop CTAs */}
        <div className="hidden items-center gap-4 md:flex">
          <Link
            to="/login"
            className="text-[13px] font-medium text-gray-500 transition-colors hover:text-gray-200"
          >
            Sign in
          </Link>
          <Link
            to="/app?demo=true"
            className="btn-primary rounded-lg px-4 py-2 text-[13px]"
          >
            Get Started
          </Link>
        </div>

        {/* Mobile hamburger */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="rounded-lg p-2 text-gray-500 transition-colors hover:bg-white/[0.04] hover:text-white md:hidden"
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {/* Mobile menu with smooth height transition */}
      <div
        className="overflow-hidden border-t transition-all duration-300 ease-in-out md:hidden"
        style={{
          maxHeight: `${menuHeight}px`,
          opacity: mobileOpen ? 1 : 0,
          borderColor: mobileOpen ? "rgba(255,255,255,0.04)" : "transparent",
        }}
      >
        <div ref={mobileMenuRef} className="bg-surface-0/95 backdrop-blur-xl">
          <div className="mx-auto max-w-6xl px-6 py-6">
            <div className="flex flex-col gap-1">
              {NAV_LINKS.map((link) => (
                <Link
                  key={link.to}
                  to={link.to}
                  onClick={() => setMobileOpen(false)}
                  className="rounded-lg px-3 py-2.5 text-sm text-gray-400 transition-colors hover:bg-white/[0.04] hover:text-white"
                >
                  {link.label}
                </Link>
              ))}
              <Link
                to="/login"
                onClick={() => setMobileOpen(false)}
                className="rounded-lg px-3 py-2.5 text-sm text-gray-400 transition-colors hover:bg-white/[0.04] hover:text-white"
              >
                Sign in
              </Link>
            </div>

            <div className="mt-4 border-t border-white/[0.04] pt-4">
              <Link
                to="/app?demo=true"
                onClick={() => setMobileOpen(false)}
                className="btn-primary block w-full rounded-lg py-2.5 text-center text-sm"
              >
                Get Started
              </Link>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
