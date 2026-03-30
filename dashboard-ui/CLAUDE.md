# dashboard-ui/ — React Dashboard

React + TypeScript + Tailwind CSS dashboard with 365 pages.

## Tech Stack
- React 18 + TypeScript
- Tailwind CSS
- Vite build system
- Lucide React icons

## Design System
- Surface-based depth hierarchy: `surface-0` through `surface-4`
- Opacity-based borders: `rgba(255,255,255,0.XX)`
- Brand cyan accent
- Inter + JetBrains Mono typography
- Premium components: `btn-primary` (gradient+glow), `btn-secondary`, `card-surface`, `card-interactive` (hover-lift)

## File Structure
```
dashboard-ui/
├── src/
│   ├── App.tsx            # Routes + lazy loading
│   ├── config/
│   │   └── products.ts    # Sidebar nav configuration
│   ├── pages/             # 365 page components
│   │   ├── AgenticMDR.tsx
│   │   ├── SituationManager.tsx
│   │   └── ...
│   └── components/        # Shared components
│       ├── MetricCard.tsx
│       ├── PageHeader.tsx
│       ├── StatusBadge.tsx
│       ├── Sidebar.tsx
│       └── ...
```

## Adding a New Page
1. Create page in `src/pages/{PageName}.tsx`
2. Add lazy import in `App.tsx`
3. Add Route in `App.tsx`
4. Add nav item in `config/products.ts`
5. Import icon from `lucide-react`

## Page Pattern
```tsx
import { useState } from "react";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "tab2" | "tab3" | "tab4";
const TABS = [...];

export default function PageName() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="..." subtitle="..." icon={...} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard ... />
      </div>
      <div className="tab-bar">...</div>
      {tab === "overview" && ...}
    </div>
  );
}
```

## UX Rules (User-Specified)
- NO purple gradients, glassmorphism, heavy background effects
- NO scroll hijacking, forced step-by-step builds, fade-ins
- NO distracting animations
- DO: clear hierarchy, readable text, obvious CTAs
- DO: fast comprehension, functional micro-interactions
