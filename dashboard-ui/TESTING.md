# Dashboard Multi-Tenant Testing Checklist

This checklist covers manual verification of multi-tenant wiring for the priority
dashboard pages introduced in issue #218. All priority pages consume
`useAuth()` + `api/client.ts` and are scoped by the JWT's `org_id` claim via
tenant-isolation middleware on the backend.

## Priority Pages

| Page                | Path                        | Backend routes                                            |
|---------------------|-----------------------------|-----------------------------------------------------------|
| Agent Firewall      | `/agent-firewall`           | `GET /api/v1/firewall/dashboard/stats`, `/stream`         |
| NHI Registry        | `/nhi-registry`             | `GET /api/v1/nhi/metrics`, `/identities`, `/shadow-ai`    |
| Cost                | `/cost`                     | `GET /api/v1/cost/summary`                                |
| Investigations      | `/investigations`           | `GET /api/v1/investigations/`                             |

## Prerequisites

1. Backend running locally: `uvicorn shieldops.api.main:app --reload`
2. Dashboard running: `cd dashboard-ui && npm run dev`
3. Two test JWTs minted for two distinct tenants (org A and org B) — see
   `scripts/mint_test_jwt.py` or the `/auth/login` endpoint.

```bash
# Set a token in the browser console before loading a page
localStorage.setItem("shieldops_token", "<jwt-here>")
```

## 1. Happy path — real API data loads

For each priority page:

- [ ] Page loads without console errors
- [ ] Metric cards populate with real values from the API (not demo fixtures)
- [ ] Primary table / grid renders rows
- [ ] Refresh button triggers a refetch (spinner spins, values update)
- [ ] Auto-refetch interval fires (15s firewall, 30s NHI, no polling on cost)

## 2. Tenant isolation

- [ ] Sign in as **tenant A**, note: total evaluations / NHI count / cost
- [ ] Log out (`logout()` from `useAuth`), confirm redirect to `/login`
- [ ] Sign in as **tenant B**, confirm numbers are different
- [ ] No records from tenant A appear in tenant B's view on any page
- [ ] Reload each page — data remains tenant-scoped (no cache leak across tenants)
  - React Query keys include `orgId`, so cache is partitioned by tenant

## 3. Empty states

Trigger empty state by using a fresh tenant with no data:

- [ ] Agent Firewall → "No evaluations recorded yet" empty state
- [ ] Agent Firewall → Tools tab → "No tool activity yet"
- [ ] Agent Firewall → Hourly tab → "No hourly data yet"
- [ ] NHI Registry → "No identities match your filters" (after clearing filters)
- [ ] NHI Registry → Shadow AI section hidden when zero detections
- [ ] Cost → "Cost analysis not configured" when billing unconfigured (501/404)
- [ ] Investigations → empty table state

## 4. Error states

### 401 Unauthorized (expired / invalid token)

- [ ] Set an expired token: `localStorage.setItem("shieldops_token", "expired.jwt.here")`
- [ ] Reload each priority page
- [ ] Page should auto-redirect to `/login` (handled in `api/client.ts`)
- [ ] `shieldops_token` is cleared from localStorage

### 403 Forbidden (wrong tenant / role)

- [ ] Use a viewer-role token on an admin-only endpoint
- [ ] Error card renders with the server's `detail` message
- [ ] Retry button visible and functional

### 500 / network failure

- [ ] Stop the backend API
- [ ] Reload each priority page
- [ ] Error state shown with "Unable to load …" message
- [ ] Retry button present and re-fetches once API is back
- [ ] React Query retries twice then surfaces error (per page `retry` config)

### 501 Not Configured

- [ ] NHI Registry with `nhi_registry_engine` not wired returns 501
- [ ] UI shows "NHI Registry not configured" CTA instead of retry
- [ ] Cost with billing unconfigured shows quick-setup guide

## 5. Auth hook sanity

- [ ] `useAuth()` decodes JWT correctly: `orgId`, `role`, `user.email` populated
- [ ] Cross-tab logout works (open two tabs, logout in one → other updates)
- [ ] Expired-token detection: `isExpired === true` when `exp` claim is past
- [ ] `isAuthenticated` gates rendering (page shows "Sign in to view …" card)

## 6. Regression

- [ ] Demo mode still works (`?demo=1` or `VITE_DEMO_MODE=1`) — routes
      resolved from fixtures via `demo/routeMap.ts` without hitting the API
- [ ] No purple gradients introduced
- [ ] Surface-based design tokens respected (`bg-surface-{0..4}`,
      `border-white/[0.06]`)
- [ ] No hardcoded tenant IDs, API URLs, or credentials

## Files Touched (issue #218)

- `dashboard-ui/src/hooks/useAuth.ts` — JWT decode + multi-tab sync + logout
- `dashboard-ui/src/api/client.ts` — `VITE_API_BASE_URL`, 401/403 handling,
  Authorization header injection, typed `ApiError`
- `dashboard-ui/src/pages/AgentFirewall.tsx` — wired to `/firewall/dashboard/*`
- `dashboard-ui/src/pages/NHIRegistry.tsx` — wired to `/nhi/*`
- `dashboard-ui/src/pages/Cost.tsx` — wired to `/cost/summary`
- `dashboard-ui/src/pages/Investigations.tsx` — wired to `/investigations/`
