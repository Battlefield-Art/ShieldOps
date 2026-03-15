import clsx from "clsx";

interface LogoProps {
  size?: "sm" | "md" | "lg";
  showText?: boolean;
  className?: string;
}

/** Custom ShieldOps logo mark — geometric shield with security heartbeat pulse. */
export default function Logo({ size = "md", showText = true, className }: LogoProps) {
  const sizes = {
    sm: { icon: "h-5 w-5", text: "text-sm" },
    md: { icon: "h-7 w-7", text: "text-lg" },
    lg: { icon: "h-10 w-10", text: "text-2xl" },
  };

  const s = sizes[size];

  return (
    <span className={clsx("inline-flex items-center gap-2", className)}>
      <svg
        viewBox="0 0 36 36"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className={s.icon}
        aria-hidden="true"
      >
        <defs>
          {/* Glow filter for the pulse line */}
          <filter id="shieldops-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="1.2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Gradient for outer shield facet */}
          <linearGradient id="shield-face" x1="18" y1="2" x2="18" y2="34" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#0e9fb8" />
            <stop offset="100%" stopColor="#0891b2" />
          </linearGradient>
        </defs>

        {/* Outer shield — clean geometric form with flat top edge */}
        <path
          d="M18 2L5 8.5v9c0 8.2 5.6 15.2 13 17.5 7.4-2.3 13-9.3 13-17.5v-9L18 2z"
          fill="url(#shield-face)"
        />

        {/* Inner shield — darker inset creating depth */}
        <path
          d="M18 5.5L8 10.5v7c0 6.4 4.2 12 10 14.2 5.8-2.2 10-7.8 10-14.2v-7L18 5.5z"
          fill="#083344"
        />

        {/* Subtle mid-layer edge highlight */}
        <path
          d="M18 5.5L8 10.5v7c0 6.4 4.2 12 10 14.2 5.8-2.2 10-7.8 10-14.2v-7L18 5.5z"
          fill="none"
          stroke="#0891b2"
          strokeWidth="0.5"
          opacity="0.4"
        />

        {/* Security heartbeat pulse — sharp, precise angles */}
        <path
          d="M8.5 18.5h3.5l1.8-3.5 2.2 7 2.5-7 1.8 3.5H24"
          stroke="#22d3ee"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="bevel"
          fill="none"
          filter="url(#shieldops-glow)"
        />

        {/* Tiny keyhole notch at shield top-center for brand identity */}
        <circle cx="18" cy="12" r="1.4" fill="#0891b2" />
        <rect x="17.4" y="12" width="1.2" height="2.4" rx="0.4" fill="#0891b2" />
      </svg>
      {showText && (
        <span className={clsx("font-semibold tracking-tight text-gray-100", s.text)}>
          Shield<span className="text-brand-400">Ops</span>
        </span>
      )}
    </span>
  );
}
