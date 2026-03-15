import { Link } from "react-router-dom";
import Logo from "../Logo";

const FOOTER_LINKS = {
  Product: [
    { label: "SRE Automation", href: "/product/sre" },
    { label: "SOC Operations", href: "/product/soc" },
    { label: "FinOps Intelligence", href: "/product/finops" },
    { label: "Compliance", href: "/product/compliance" },
  ],
  Resources: [
    { label: "Docs", href: "/docs" },
    { label: "API Reference", href: "/docs/api" },
    { label: "Changelog", href: "/changelog" },
    { label: "Status", href: "https://status.shieldops.io", external: true },
  ],
  Company: [
    { label: "About", href: "/about" },
    { label: "Blog", href: "/blog" },
    { label: "Careers", href: "/careers" },
    { label: "Contact", href: "mailto:founders@shieldops.io", external: true },
  ],
  Legal: [
    { label: "Privacy", href: "/privacy" },
    { label: "Terms", href: "/terms" },
    { label: "Security", href: "/security" },
  ],
};

export default function Footer() {
  return (
    <footer className="border-t border-gray-800 bg-gray-950 px-6 py-14">
      <div className="mx-auto max-w-6xl">
        {/* Top: logo + columns */}
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-5">
          {/* Logo + tagline */}
          <div className="lg:col-span-1">
            <Logo size="sm" />
            <p className="mt-3 text-sm text-gray-500">
              Autonomous SRE agents that investigate, remediate, and learn.
            </p>
          </div>

          {/* Link columns */}
          {Object.entries(FOOTER_LINKS).map(([category, links]) => (
            <div key={category}>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                {category}
              </h4>
              <ul className="mt-3 space-y-2">
                {links.map((link) => (
                  <li key={link.label}>
                    {"external" in link && link.external ? (
                      <a
                        href={link.href}
                        className="text-sm text-gray-500 transition-colors hover:text-gray-300"
                        target={link.href.startsWith("http") ? "_blank" : undefined}
                        rel={
                          link.href.startsWith("http")
                            ? "noopener noreferrer"
                            : undefined
                        }
                      >
                        {link.label}
                      </a>
                    ) : (
                      <Link
                        to={link.href}
                        className="text-sm text-gray-500 transition-colors hover:text-gray-300"
                      >
                        {link.label}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom: copyright */}
        <div className="mt-12 border-t border-gray-800 pt-6">
          <p className="text-xs text-gray-600">
            &copy; {new Date().getFullYear()} ShieldOps. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}
