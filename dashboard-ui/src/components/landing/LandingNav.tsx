import { useState, useEffect } from "react";
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

  useEffect(() => {
    function handleScroll() {
      setScrolled(window.scrollY > 8);
    }
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <nav
      className={clsx(
        "fixed top-0 z-50 w-full transition-colors duration-200",
        scrolled
          ? "border-b border-gray-800/60 bg-gray-950/95 backdrop-blur-sm"
          : "border-b border-transparent bg-transparent",
      )}
    >
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3.5">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2">
          <Logo />
        </Link>

        {/* Desktop center links */}
        <div className="hidden items-center gap-1 md:flex">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.to}
              to={link.to}
              className="rounded-md px-3 py-2 text-sm text-gray-400 transition-colors hover:text-gray-200"
            >
              {link.label}
            </Link>
          ))}
        </div>

        {/* Desktop CTAs */}
        <div className="hidden items-center gap-4 md:flex">
          <Link
            to="/login"
            className="text-sm text-gray-400 transition-colors hover:text-gray-200"
          >
            Sign in
          </Link>
          <Link
            to="/app?demo=true"
            className="rounded-md bg-cyan-700 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-cyan-600"
          >
            Get Started
          </Link>
        </div>

        {/* Mobile hamburger */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="rounded-md p-2 text-gray-400 transition-colors hover:bg-gray-900 hover:text-white md:hidden"
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="border-t border-gray-800 bg-gray-950 md:hidden">
          <div className="mx-auto max-w-6xl px-6 py-6">
            <div className="flex flex-col gap-1">
              {NAV_LINKS.map((link) => (
                <Link
                  key={link.to}
                  to={link.to}
                  onClick={() => setMobileOpen(false)}
                  className="rounded-md px-3 py-2.5 text-sm text-gray-300 transition-colors hover:bg-gray-900 hover:text-white"
                >
                  {link.label}
                </Link>
              ))}
              <Link
                to="/login"
                onClick={() => setMobileOpen(false)}
                className="rounded-md px-3 py-2.5 text-sm text-gray-300 transition-colors hover:bg-gray-900 hover:text-white"
              >
                Sign in
              </Link>
            </div>

            <div className="mt-4 border-t border-gray-800 pt-4">
              <Link
                to="/app?demo=true"
                onClick={() => setMobileOpen(false)}
                className="block rounded-md bg-cyan-700 px-4 py-2.5 text-center text-sm font-medium text-white transition-colors hover:bg-cyan-600"
              >
                Get Started
              </Link>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
