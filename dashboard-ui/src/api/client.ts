/** HTTP client for the ShieldOps API.
 *
 * Centralized fetch wrapper — injects the JWT Authorization header, handles
 * 401 (auto-logout), 403 (friendly org-mismatch error), and demo mode.
 * Base URL is resolved from VITE_API_BASE_URL with a sensible fallback.
 */

import { isDemoMode } from "../demo/config";
import { resolveRoute } from "../demo/routeMap";

const TOKEN_KEY = "shieldops_token";

function resolveApiBase(): string {
  const env = (import.meta.env.VITE_API_BASE_URL ?? import.meta.env.VITE_API_URL) as
    | string
    | undefined;
  if (env && env.length > 0) {
    return env.replace(/\/+$/, "");
  }
  return "/api/v1";
}

const API_BASE = resolveApiBase();

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  // Demo mode: resolve from fixtures instead of making real HTTP calls
  if (isDemoMode()) {
    await new Promise((r) => setTimeout(r, 50 + Math.random() * 150));
    const body = options.body ? JSON.parse(options.body as string) : undefined;
    return resolveRoute(path, body) as T;
  }

  const token = localStorage.getItem(TOKEN_KEY);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) ?? {}),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
    throw new ApiError(401, "Session expired — please sign in again.");
  }

  if (res.status === 403) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    const detail =
      body.detail ?? "You don't have access to this resource for the current organization.";
    throw new ApiError(403, detail);
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail ?? res.statusText);
  }

  return res.json() as Promise<T>;
}

// ── Convenience methods ─────────────────────────────────────────────

export function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    body: body ? JSON.stringify(body) : undefined,
  });
}

export function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "PUT",
    body: body ? JSON.stringify(body) : undefined,
  });
}

export function del<T>(path: string): Promise<T> {
  return request<T>(path, { method: "DELETE" });
}

export { ApiError };
