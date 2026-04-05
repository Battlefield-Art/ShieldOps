/**
 * Natural Language Query Bar — the "Kill SIEM" UI component.
 *
 * Users type questions in English, ShieldOps translates to SQL,
 * executes against the data lake, and returns markdown results.
 *
 * Usage:
 *   <NLQueryBar onResult={(result) => setResults(result)} />
 */

import { useState, useCallback } from "react";
import { Search, Loader2, Sparkles, Clock } from "lucide-react";
import { useAPIAction } from "../hooks/useAPI";

interface QueryResult {
  markdown: string;
  format: "table" | "empty" | "error";
  row_count?: number;
  sql?: string;
}

interface NLQueryBarProps {
  onResult?: (result: QueryResult) => void;
  placeholder?: string;
}

const SUGGESTED_QUERIES = [
  "Show me all critical alerts in the last 24 hours",
  "What are the top event sources this week?",
  "How many failed login attempts today?",
  "Show me events from CrowdStrike with high severity",
  "Weekly compliance summary",
];

export default function NLQueryBar({ onResult, placeholder }: NLQueryBarProps) {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<QueryResult | null>(null);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [history, setHistory] = useState<string[]>([]);

  const { execute, loading } = useAPIAction<
    { question: string },
    QueryResult
  >("/query/ask");

  const handleSubmit = useCallback(
    async (q?: string) => {
      const question = q || query;
      if (!question.trim()) return;

      const res = await execute({ question });
      if (res) {
        setResult(res);
        onResult?.(res);
        setHistory((prev) => [question, ...prev.slice(0, 9)]);
      }
      setShowSuggestions(false);
    },
    [query, execute, onResult]
  );

  return (
    <div className="space-y-4">
      {/* Query Input */}
      <div className="relative">
        <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-[var(--surface-1)] px-4 py-3 focus-within:border-cyan-500/50 focus-within:ring-1 focus-within:ring-cyan-500/20">
          <Sparkles className="h-5 w-5 text-cyan-400 shrink-0" />
          <input
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setShowSuggestions(e.target.value === "");
            }}
            onFocus={() => !query && setShowSuggestions(true)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            placeholder={placeholder || "Ask anything about your security data..."}
            className="flex-1 bg-transparent text-white placeholder-white/40 outline-none text-sm"
          />
          {loading ? (
            <Loader2 className="h-5 w-5 text-cyan-400 animate-spin" />
          ) : (
            <button
              onClick={() => handleSubmit()}
              className="rounded-md bg-cyan-500/20 px-3 py-1 text-xs text-cyan-300 hover:bg-cyan-500/30 transition-colors"
            >
              <Search className="h-4 w-4" />
            </button>
          )}
        </div>

        {/* Suggestions Dropdown */}
        {showSuggestions && (
          <div className="absolute z-10 mt-1 w-full rounded-lg border border-white/10 bg-[var(--surface-2)] p-2 shadow-xl">
            <div className="text-xs text-white/40 px-2 py-1 mb-1">Suggested queries</div>
            {SUGGESTED_QUERIES.map((sq) => (
              <button
                key={sq}
                onClick={() => {
                  setQuery(sq);
                  handleSubmit(sq);
                }}
                className="w-full text-left rounded-md px-3 py-2 text-sm text-white/70 hover:bg-white/5 hover:text-white transition-colors"
              >
                {sq}
              </button>
            ))}
            {history.length > 0 && (
              <>
                <div className="text-xs text-white/40 px-2 py-1 mt-2 mb-1 flex items-center gap-1">
                  <Clock className="h-3 w-3" /> Recent
                </div>
                {history.slice(0, 3).map((hq, i) => (
                  <button
                    key={i}
                    onClick={() => {
                      setQuery(hq);
                      handleSubmit(hq);
                    }}
                    className="w-full text-left rounded-md px-3 py-2 text-sm text-white/50 hover:bg-white/5 hover:text-white transition-colors"
                  >
                    {hq}
                  </button>
                ))}
              </>
            )}
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="rounded-lg border border-white/10 bg-[var(--surface-1)] p-4">
          {result.format === "error" ? (
            <div className="text-red-400 text-sm">{result.markdown}</div>
          ) : result.format === "empty" ? (
            <div className="text-white/50 text-sm">{result.markdown}</div>
          ) : (
            <div className="prose prose-invert prose-sm max-w-none">
              <pre className="whitespace-pre-wrap text-xs text-white/80 font-mono">
                {result.markdown}
              </pre>
              {result.row_count !== undefined && (
                <div className="mt-2 text-xs text-white/40">
                  {result.row_count} rows returned
                  {result.sql && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-cyan-400/60 hover:text-cyan-400">
                        View SQL
                      </summary>
                      <code className="block mt-1 text-white/30">{result.sql}</code>
                    </details>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
