import { useState, useRef, useEffect } from "react";
import { Send, Paperclip, Sparkles, ChevronDown } from "lucide-react";
import clsx from "clsx";

interface AgentPromptInputProps {
  onSubmit: (prompt: string, context?: string) => void;
  placeholder?: string;
  disabled?: boolean;
}

const QUICK_CONTEXTS = [
  { label: "Slack", icon: "#", color: "text-brand-400" },
  { label: "PagerDuty", icon: "P", color: "text-emerald-400" },
  { label: "Splunk", icon: "S", color: "text-green-400" },
  { label: "Datadog", icon: "D", color: "text-sky-400" },
  { label: "Jira", icon: "J", color: "text-blue-400" },
  { label: "GitHub", icon: "G", color: "text-gray-300" },
  { label: "AWS", icon: "A", color: "text-amber-400" },
  { label: "GCP", icon: "G", color: "text-red-400" },
  { label: "Azure", icon: "A", color: "text-sky-400" },
];

export default function AgentPromptInput({
  onSubmit,
  placeholder = "Describe what you want to automate...",
  disabled = false,
}: AgentPromptInputProps) {
  const [prompt, setPrompt] = useState("");
  const [selectedContext, setSelectedContext] = useState<string | null>(null);
  const [showContextMenu, setShowContextMenu] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setShowContextMenu(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Auto-resize textarea
  useEffect(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = "auto";
      textarea.style.height = `${Math.min(textarea.scrollHeight, 160)}px`;
    }
  }, [prompt]);

  function handleSubmit() {
    if (!prompt.trim() || disabled) return;
    onSubmit(prompt.trim(), selectedContext ?? undefined);
    setPrompt("");
    setSelectedContext(null);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  }

  const hasContent = prompt.trim().length > 0;

  return (
    <div className="w-full max-w-3xl mx-auto">
      <div
        className={clsx(
          "relative rounded-2xl border transition-all duration-250",
          disabled
            ? "border-white/[0.04] opacity-60"
            : [
                "border-white/[0.08] bg-surface-2",
                "focus-within:border-brand-500/30",
                hasContent && "shadow-glow-brand",
              ],
        )}
        style={{
          boxShadow: !disabled
            ? "0 0 0 1px rgba(255,255,255,0.02), 0 2px 8px rgba(0,0,0,0.3)"
            : undefined,
        }}
      >
        {/* Context badge */}
        {selectedContext && (
          <div className="flex items-center gap-2 px-4 pt-3">
            <span className="inline-flex items-center gap-1.5 rounded-full bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-300 ring-1 ring-inset ring-white/[0.06]">
              <span className="h-1.5 w-1.5 rounded-full bg-brand-400" />
              {selectedContext}
              <button
                onClick={() => setSelectedContext(null)}
                className="ml-1 text-gray-600 hover:text-gray-300 transition-colors"
              >
                x
              </button>
            </span>
          </div>
        )}

        {/* Textarea */}
        <textarea
          ref={textareaRef}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          disabled={disabled}
          rows={1}
          className="w-full resize-none bg-transparent px-4 py-4 text-sm text-gray-100 placeholder-gray-600 focus:outline-none leading-relaxed"
        />

        {/* Bottom bar */}
        <div className="flex items-center justify-between border-t border-white/[0.04] px-3 py-2">
          <div className="flex items-center gap-0.5">
            {/* Attach context */}
            <div className="relative" ref={contextMenuRef}>
              <button
                onClick={() => setShowContextMenu(!showContextMenu)}
                className="flex items-center gap-1 rounded-lg px-2 py-1.5 text-xs text-gray-600 transition-colors hover:bg-white/[0.04] hover:text-gray-400"
                title="Attach integration context"
              >
                <Paperclip className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Context</span>
                <ChevronDown className="h-3 w-3" />
              </button>

              {showContextMenu && (
                <div className="absolute bottom-full left-0 mb-2 w-48 rounded-xl border border-white/[0.08] bg-surface-3 py-1 shadow-elevated animate-fade-in">
                  <p className="px-3 py-1.5 text-[11px] font-medium text-gray-600 uppercase tracking-wider">
                    Connect to
                  </p>
                  {QUICK_CONTEXTS.map((ctx) => (
                    <button
                      key={ctx.label}
                      onClick={() => {
                        setSelectedContext(ctx.label);
                        setShowContextMenu(false);
                      }}
                      className="flex w-full items-center gap-2.5 px-3 py-2 text-sm text-gray-400 hover:bg-white/[0.04] hover:text-gray-200 transition-colors"
                    >
                      <span
                        className={clsx(
                          "flex h-6 w-6 items-center justify-center rounded-md bg-white/[0.04] text-xs font-bold",
                          ctx.color,
                        )}
                      >
                        {ctx.icon}
                      </span>
                      {ctx.label}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* AI badge */}
            <div className="flex items-center gap-1 rounded-lg px-2 py-1.5 text-xs text-brand-500/50">
              <Sparkles className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">AI-Powered</span>
            </div>
          </div>

          {/* Submit */}
          <button
            onClick={handleSubmit}
            disabled={!hasContent || disabled}
            className={clsx(
              "flex items-center gap-1.5 rounded-xl px-4 py-2 text-sm font-medium transition-all duration-200",
              hasContent && !disabled
                ? "btn-primary"
                : "bg-white/[0.04] text-gray-600 cursor-not-allowed",
            )}
          >
            <Send className="h-3.5 w-3.5" />
            Run Agent
          </button>
        </div>
      </div>

      <p className="mt-2.5 text-center text-[11px] text-gray-700">
        Press Enter to run &middot; Shift+Enter for new line &middot; All actions gated by OPA policies
      </p>
    </div>
  );
}
