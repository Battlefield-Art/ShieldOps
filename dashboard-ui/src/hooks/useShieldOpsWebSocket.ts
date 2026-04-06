/**
 * useShieldOpsWebSocket
 *
 * React hook for the unified ShieldOps real-time event stream. Connects to
 * `/ws/realtime`, subscribes to the authenticated user's org, and invokes
 * `onEvent` for every inbound message. Auto-reconnects with exponential
 * backoff (1s → 60s) and cleans up on unmount.
 *
 * Event envelope:
 *   { type: string; org_id: string; data: unknown; ts: number }
 *
 * Supported event types include:
 *   - "subscribed"          (handshake)
 *   - "ping"                (server heartbeat — automatically ponged)
 *   - "agent_run_complete"
 *   - "agent_status_change"
 *   - "new_situation"
 *   - "firewall_event"
 *   - "metric_update"
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export interface RealtimeEvent<T = unknown> {
  type: string;
  org_id?: string;
  data: T;
  ts: number;
}

export type ConnectionState =
  | "idle"
  | "connecting"
  | "open"
  | "reconnecting"
  | "closed";

export interface UseShieldOpsWebSocketOptions {
  /** Invoked for every non-control event from the server. */
  onEvent?: (event: RealtimeEvent) => void;
  /** Optional JWT override. Defaults to localStorage "shieldops_token". */
  token?: string;
  /** Override the base WebSocket URL (e.g. "wss://api.example.com"). */
  baseUrl?: string;
  /** Disable automatic connection. Useful for tests. */
  enabled?: boolean;
}

export interface UseShieldOpsWebSocketResult {
  state: ConnectionState;
  lastEvent: RealtimeEvent | null;
  send: (payload: unknown) => void;
  disconnect: () => void;
}

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 60_000;

function resolveWsUrl(baseUrl: string | undefined, token: string): string {
  if (baseUrl) {
    return `${baseUrl.replace(/\/$/, "")}/ws/realtime?token=${encodeURIComponent(token)}`;
  }
  if (typeof window === "undefined") {
    return `ws://localhost/ws/realtime?token=${encodeURIComponent(token)}`;
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws/realtime?token=${encodeURIComponent(token)}`;
}

function resolveToken(explicit: string | undefined): string {
  if (explicit) return explicit;
  if (typeof window === "undefined") return "";
  try {
    return window.localStorage.getItem("shieldops_token") ?? "";
  } catch {
    return "";
  }
}

export function useShieldOpsWebSocket(
  options: UseShieldOpsWebSocketOptions = {},
): UseShieldOpsWebSocketResult {
  const { onEvent, token: tokenOverride, baseUrl, enabled = true } = options;

  const [state, setState] = useState<ConnectionState>("idle");
  const [lastEvent, setLastEvent] = useState<RealtimeEvent | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef<number>(INITIAL_BACKOFF_MS);
  const shouldReconnectRef = useRef<boolean>(true);
  const onEventRef = useRef<typeof onEvent>(onEvent);

  // Keep the latest onEvent without re-triggering the connection effect.
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const token = useMemo(() => resolveToken(tokenOverride), [tokenOverride]);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!enabled) return;
    if (!token) {
      setState("closed");
      return;
    }
    if (typeof WebSocket === "undefined") {
      setState("closed");
      return;
    }

    clearReconnectTimer();
    setState(wsRef.current ? "reconnecting" : "connecting");

    let ws: WebSocket;
    try {
      ws = new WebSocket(resolveWsUrl(baseUrl, token));
    } catch {
      scheduleReconnect();
      return;
    }
    wsRef.current = ws;

    ws.onopen = () => {
      backoffRef.current = INITIAL_BACKOFF_MS;
      setState("open");
    };

    ws.onmessage = (raw) => {
      let parsed: RealtimeEvent;
      try {
        parsed = JSON.parse(raw.data) as RealtimeEvent;
      } catch {
        return;
      }
      // Respond to server heartbeats transparently.
      if (parsed.type === "ping") {
        try {
          ws.send("pong");
        } catch {
          /* noop */
        }
        return;
      }
      setLastEvent(parsed);
      onEventRef.current?.(parsed);
    };

    ws.onerror = () => {
      // onclose will fire next; let it handle reconnect.
    };

    ws.onclose = () => {
      wsRef.current = null;
      if (shouldReconnectRef.current) {
        scheduleReconnect();
      } else {
        setState("closed");
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, token, baseUrl, clearReconnectTimer]);

  const scheduleReconnect = useCallback(() => {
    setState("reconnecting");
    const delay = backoffRef.current;
    backoffRef.current = Math.min(delay * 2, MAX_BACKOFF_MS);
    reconnectTimerRef.current = setTimeout(() => {
      if (shouldReconnectRef.current) connect();
    }, delay);
  }, [connect]);

  const disconnect = useCallback(() => {
    shouldReconnectRef.current = false;
    clearReconnectTimer();
    if (wsRef.current) {
      try {
        wsRef.current.close();
      } catch {
        /* noop */
      }
      wsRef.current = null;
    }
    setState("closed");
  }, [clearReconnectTimer]);

  const send = useCallback((payload: unknown) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
      ws.send(typeof payload === "string" ? payload : JSON.stringify(payload));
    } catch {
      /* noop */
    }
  }, []);

  useEffect(() => {
    shouldReconnectRef.current = true;
    connect();
    return () => {
      shouldReconnectRef.current = false;
      clearReconnectTimer();
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {
          /* noop */
        }
        wsRef.current = null;
      }
    };
  }, [connect, clearReconnectTimer]);

  return { state, lastEvent, send, disconnect };
}

export default useShieldOpsWebSocket;
