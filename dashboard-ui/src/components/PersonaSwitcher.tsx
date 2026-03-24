import { useState, useRef, useEffect } from "react";
import {
  ChevronDown,
  Shield,
  ShieldAlert,
  Server,
  DollarSign,
  Code,
  UserCog,
  Eye,
} from "lucide-react";
import clsx from "clsx";
import type { LucideIcon } from "lucide-react";

export interface Persona {
  id: string;
  label: string;
  description: string;
  icon: LucideIcon;
  color: string;
  bgColor: string;
}

export const PERSONAS: Persona[] = [
  {
    id: "sre",
    label: "SRE Engineer",
    description: "Incident response, reliability, scaling",
    icon: Server,
    color: "text-brand-400",
    bgColor: "bg-brand-500/[0.08]",
  },
  {
    id: "security",
    label: "Security Analyst",
    description: "Threat hunting, vulnerability management",
    icon: Shield,
    color: "text-red-400",
    bgColor: "bg-red-500/[0.08]",
  },
  {
    id: "finops",
    label: "FinOps Manager",
    description: "Cost optimization, budget management",
    icon: DollarSign,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/[0.08]",
  },
  {
    id: "devops",
    label: "DevOps Engineer",
    description: "CI/CD, deployments, infrastructure",
    icon: Code,
    color: "text-sky-400",
    bgColor: "bg-sky-500/[0.08]",
  },
  {
    id: "manager",
    label: "Engineering Manager",
    description: "Team metrics, capacity, planning",
    icon: UserCog,
    color: "text-amber-400",
    bgColor: "bg-amber-500/[0.08]",
  },
  {
    id: "ai_security",
    label: "AI Security",
    description: "Agent firewall, NHI, MCP security, SOC",
    icon: ShieldAlert,
    color: "text-red-400",
    bgColor: "bg-red-500/[0.08]",
  },
  {
    id: "observer",
    label: "Observer / Auditor",
    description: "Read-only compliance and audit views",
    icon: Eye,
    color: "text-gray-400",
    bgColor: "bg-white/[0.04]",
  },
];

interface PersonaSwitcherProps {
  selected: string;
  onChange: (personaId: string) => void;
}

export default function PersonaSwitcher({ selected, onChange }: PersonaSwitcherProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const current = PERSONAS.find((p) => p.id === selected) ?? PERSONAS[0];

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2.5 rounded-xl border border-white/[0.06] bg-surface-2 px-3 py-2 text-sm transition-all duration-150 hover:border-white/[0.1] hover:bg-surface-3"
      >
        <div className={clsx("flex h-6 w-6 items-center justify-center rounded-lg", current.bgColor)}>
          <current.icon className={clsx("h-3.5 w-3.5", current.color)} />
        </div>
        <span className="text-gray-300 font-medium text-[13px]">{current.label}</span>
        <ChevronDown className={clsx("h-3.5 w-3.5 text-gray-600 transition-transform", open && "rotate-180")} />
      </button>

      {open && (
        <div className="absolute left-0 top-full z-50 mt-2 w-72 rounded-2xl border border-white/[0.08] bg-surface-3 p-1.5 shadow-elevated animate-fade-in">
          <p className="px-3 py-2 section-heading">
            Switch Persona
          </p>
          {PERSONAS.map((persona) => (
            <button
              key={persona.id}
              onClick={() => {
                onChange(persona.id);
                setOpen(false);
              }}
              className={clsx(
                "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 transition-colors",
                selected === persona.id
                  ? "bg-white/[0.04] text-white"
                  : "text-gray-500 hover:bg-white/[0.03] hover:text-gray-300",
              )}
            >
              <div className={clsx("flex h-8 w-8 items-center justify-center rounded-lg", persona.bgColor)}>
                <persona.icon className={clsx("h-4 w-4", persona.color)} />
              </div>
              <div className="text-left">
                <p className="text-[13px] font-medium">{persona.label}</p>
                <p className="text-[11px] text-gray-600">{persona.description}</p>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
