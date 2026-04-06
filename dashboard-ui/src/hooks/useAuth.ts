/**
 * Authentication hook for multi-tenant dashboard.
 *
 * Decodes the JWT from localStorage and exposes the current user,
 * org_id, and role — used to scope API calls by tenant.
 *
 * Usage:
 *   const { token, user, orgId, role, isAuthenticated, logout } = useAuth();
 */

import { useCallback, useEffect, useState } from "react";

const TOKEN_KEY = "shieldops_token";

export type UserRole = "admin" | "operator" | "viewer";

export interface AuthUser {
  sub: string;
  email?: string;
  name?: string;
  org_id: string;
  role: UserRole;
  exp?: number;
}

export interface UseAuthResult {
  token: string | null;
  user: AuthUser | null;
  orgId: string | null;
  role: UserRole | null;
  isAuthenticated: boolean;
  isExpired: boolean;
  logout: () => void;
}

/**
 * Decode a JWT payload without verifying the signature.
 * Verification happens server-side — the client only needs the claims.
 */
export function decodeJwt(token: string): AuthUser | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = parts[1];
    // base64url -> base64
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = atob(padded);
    const claims = JSON.parse(json) as Record<string, unknown>;

    // Normalize: prefer explicit org_id claim, else tenant_id, else fall back to sub
    const orgId =
      (claims.org_id as string) ??
      (claims.tenant_id as string) ??
      (claims.sub as string) ??
      "";
    const role = ((claims.role as string) ?? "viewer") as UserRole;

    return {
      sub: (claims.sub as string) ?? "",
      email: claims.email as string | undefined,
      name: claims.name as string | undefined,
      org_id: orgId,
      role,
      exp: claims.exp as number | undefined,
    };
  } catch {
    return null;
  }
}

export function useAuth(): UseAuthResult {
  const [token, setToken] = useState<string | null>(() =>
    typeof window !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null,
  );

  // Keep token in sync with localStorage across tabs
  useEffect(() => {
    function onStorage(e: StorageEvent) {
      if (e.key === TOKEN_KEY) {
        setToken(e.newValue);
      }
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const user = token ? decodeJwt(token) : null;
  const now = Math.floor(Date.now() / 1000);
  const isExpired = !!(user?.exp && user.exp < now);
  const isAuthenticated = !!user && !isExpired;

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
  }, []);

  return {
    token,
    user,
    orgId: user?.org_id ?? null,
    role: user?.role ?? null,
    isAuthenticated,
    isExpired,
    logout,
  };
}

export default useAuth;
