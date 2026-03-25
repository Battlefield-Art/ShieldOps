import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Loader2, KeyRound } from "lucide-react";
import { post, get, ApiError } from "../api/client";
import type { TokenResponse, User } from "../api/types";
import { useAuthStore } from "../store/auth";

const API_BASE = "/api/v1";

export default function Login() {
  const navigate = useNavigate();
  const { setAuth } = useAuthStore();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const { access_token } = await post<TokenResponse>("/auth/login", {
        email,
        password,
      });

      // Persist the token so the next get() call includes it
      localStorage.setItem("shieldops_token", access_token);

      const user = await get<User>("/auth/me");
      setAuth(access_token, user);
      navigate("/app", { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  function handleSSOLogin() {
    window.location.href = `${API_BASE}/auth/oidc/login`;
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-0 px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-500/10 ring-1 ring-brand-500/20 shadow-glow-brand">
            <Shield className="h-8 w-8 text-brand-500" />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-gray-50">ShieldOps</h1>
          <p className="mt-1.5 text-sm text-gray-500">
            Autonomous SRE Platform
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-white/[0.06] bg-surface-2 p-6 shadow-elevated">
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label
                htmlFor="email"
                className="mb-1.5 block text-sm font-medium text-gray-400"
              >
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="w-full rounded-lg border border-white/[0.08] bg-white/[0.05] px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition-all duration-150 focus:border-brand-500/60 focus:ring-2 focus:ring-brand-500/20"
              />
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor="password"
                className="mb-1.5 block text-sm font-medium text-gray-400"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                className="w-full rounded-lg border border-white/[0.08] bg-white/[0.05] px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition-all duration-150 focus:border-brand-500/60 focus:ring-2 focus:ring-brand-500/20"
              />
            </div>

            {/* Error */}
            {error && (
              <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-medium text-white shadow-glow-brand transition-all duration-150 hover:bg-brand-500 hover:shadow-glow-brand-lg disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>

          {/* SSO Divider */}
          <div className="my-5 flex items-center gap-3">
            <div className="h-px flex-1 bg-surface-3" />
            <span className="text-xs text-gray-600">or</span>
            <div className="h-px flex-1 bg-surface-3" />
          </div>

          {/* SSO Button */}
          <button
            type="button"
            onClick={handleSSOLogin}
            className="btn-secondary w-full justify-center py-2.5"
          >
            <KeyRound className="h-4 w-4" />
            Sign in with SSO
          </button>
        </div>
      </div>
    </div>
  );
}
