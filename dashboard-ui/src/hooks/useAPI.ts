/**
 * Generic API hook for fetching data from the ShieldOps backend.
 *
 * Usage:
 *   const { data, loading, error, refetch } = useAPI<SituationsResponse>("/situations");
 *   const { data } = useAPI<StatsResponse>("/situations/stats");
 */

import { useState, useEffect, useCallback } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";

interface UseAPIResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useAPI<T>(
  path: string,
  options?: {
    /** Auto-fetch on mount. Default: true */
    autoFetch?: boolean;
    /** Polling interval in ms. 0 = no polling. Default: 0 */
    pollInterval?: number;
    /** Query parameters */
    params?: Record<string, string | number | undefined>;
  }
): UseAPIResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { autoFetch = true, pollInterval = 0, params } = options || {};

  const buildUrl = useCallback(() => {
    const url = new URL(`${API_BASE}${path}`);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      });
    }
    return url.toString();
  }, [path, params]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem("shieldops_token") || "";
      const res = await fetch(buildUrl(), {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      if (!res.ok) {
        throw new Error(`API error: ${res.status} ${res.statusText}`);
      }
      const json = await res.json();
      setData(json as T);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [buildUrl]);

  useEffect(() => {
    if (autoFetch) {
      fetchData();
    }
  }, [autoFetch, fetchData]);

  useEffect(() => {
    if (pollInterval > 0) {
      const interval = setInterval(fetchData, pollInterval);
      return () => clearInterval(interval);
    }
  }, [pollInterval, fetchData]);

  return { data, loading, error, refetch: fetchData };
}

/**
 * POST hook for triggering actions.
 */
export function useAPIAction<TRequest, TResponse>(path: string) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const execute = useCallback(
    async (body: TRequest): Promise<TResponse | null> => {
      setLoading(true);
      setError(null);
      try {
        const token = localStorage.getItem("shieldops_token") || "";
        const res = await fetch(`${API_BASE}${path}`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        return (await res.json()) as TResponse;
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
        return null;
      } finally {
        setLoading(false);
      }
    },
    [path]
  );

  return { execute, loading, error };
}

export default useAPI;
