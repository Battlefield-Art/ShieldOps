import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        gray: {
          925: "#0d1117",
          850: "#1a1f2e",
          875: "#141a27",
        },
        brand: {
          50: "#ecfeff",
          100: "#cffafe",
          200: "#a5f3fc",
          300: "#67e8f9",
          400: "#22d3ee",
          500: "#06b6d4",
          600: "#0891b2",
          700: "#0e7490",
          800: "#155e75",
          900: "#164e63",
          950: "#083344",
        },
        surface: {
          0: "#0a0e17",
          1: "#0f1420",
          2: "#151b2b",
          3: "#1c2333",
          4: "#232b3e",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
        display: ["Inter", "system-ui", "sans-serif"],
      },
      fontSize: {
        "2xs": ["0.625rem", { lineHeight: "0.875rem" }],
      },
      boxShadow: {
        "glow-brand": "0 0 20px -5px rgba(6, 182, 212, 0.15)",
        "glow-brand-lg": "0 0 40px -8px rgba(6, 182, 212, 0.2)",
        "glow-brand-xl": "0 0 60px -12px rgba(6, 182, 212, 0.25)",
        "card": "0 1px 3px 0 rgba(0, 0, 0, 0.3), 0 1px 2px -1px rgba(0, 0, 0, 0.3)",
        "card-hover": "0 4px 16px 0 rgba(0, 0, 0, 0.45), 0 2px 4px -2px rgba(0, 0, 0, 0.3)",
        "elevated": "0 12px 32px -4px rgba(0, 0, 0, 0.5), 0 4px 12px -2px rgba(0, 0, 0, 0.3)",
        "inner-light": "inset 0 1px 0 0 rgba(255, 255, 255, 0.04)",
        "inner-glow": "inset 0 0 20px 0 rgba(6, 182, 212, 0.03)",
        "ring-brand": "0 0 0 1px rgba(6, 182, 212, 0.15)",
        "depth": "0 0 0 1px rgba(255, 255, 255, 0.03), 0 1px 2px rgba(0, 0, 0, 0.4)",
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-conic": "conic-gradient(var(--tw-gradient-stops))",
        "noise": "url(\"data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E\")",
        "shimmer-gradient": "linear-gradient(110deg, transparent 25%, rgba(255,255,255,0.03) 50%, transparent 75%)",
      },
      keyframes: {
        "slide-in-right": {
          "0%": { transform: "translateX(100%)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        "slide-out-right": {
          "0%": { transform: "translateX(0)", opacity: "1" },
          "100%": { transform: "translateX(100%)", opacity: "0" },
        },
        "fade-in-up": {
          "0%": { transform: "translateY(8px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        "pulse-subtle": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.7" },
        },
        "glow-pulse": {
          "0%, 100%": { boxShadow: "0 0 20px -5px rgba(6, 182, 212, 0.15)" },
          "50%": { boxShadow: "0 0 30px -5px rgba(6, 182, 212, 0.25)" },
        },
        "border-shine": {
          "0%": { backgroundPosition: "0% 50%" },
          "50%": { backgroundPosition: "100% 50%" },
          "100%": { backgroundPosition: "0% 50%" },
        },
      },
      animation: {
        "slide-in-right": "slide-in-right 0.3s ease-out",
        "slide-out-right": "slide-out-right 0.3s ease-in",
        "fade-in-up": "fade-in-up 0.35s ease-out",
        "fade-in": "fade-in 0.2s ease-out",
        shimmer: "shimmer 2s ease-in-out infinite",
        "pulse-subtle": "pulse-subtle 2s ease-in-out infinite",
        "glow-pulse": "glow-pulse 3s ease-in-out infinite",
        "border-shine": "border-shine 3s ease infinite",
      },
      borderRadius: {
        "2xl": "1rem",
        "3xl": "1.25rem",
      },
      spacing: {
        "18": "4.5rem",
        "88": "22rem",
      },
      transitionDuration: {
        "250": "250ms",
      },
    },
  },
  plugins: [],
} satisfies Config;
