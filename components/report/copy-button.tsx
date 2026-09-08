"use client";

import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";

interface CopyButtonProps {
  /** Exactly what lands on the clipboard. */
  value: string;
  /** Names the thing being copied, for screen readers. */
  label: string;
  className?: string;
}

type CopyState = "idle" | "copied" | "failed";

/**
 * Copy one remediation snippet.
 *
 * The confirmation is visible AND announced: a sighted user sees the label
 * change, a screen-reader user hears the live region. A colour flash alone
 * would tell neither of them reliably.
 *
 * Failure is reported rather than swallowed. `navigator.clipboard` needs a
 * secure context, so on plain http this genuinely does not work — and a button
 * that silently does nothing is worse than one that says so, because the
 * snippet is still there to select by hand.
 */
export function CopyButton({ value, label, className }: CopyButtonProps) {
  const [state, setState] = useState<CopyState>("idle");
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (resetTimer.current) clearTimeout(resetTimer.current);
    };
  }, []);

  async function handleCopy() {
    if (resetTimer.current) clearTimeout(resetTimer.current);

    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }

    resetTimer.current = setTimeout(() => setState("idle"), 2000);
  }

  return (
    <>
      <Button
        type="button"
        size="sm"
        variant="secondary"
        onClick={handleCopy}
        aria-label={
          state === "copied" ? `${label} copied` : `Copy ${label}`
        }
        className={cn(
          "shrink-0 font-mono text-2xs tracking-label uppercase",
          state === "copied" && "border-pass-edge text-pass",
          state === "failed" && "border-critical-edge text-critical",
          className,
        )}
      >
        {state === "copied" ? "Copied" : state === "failed" ? "Failed" : "Copy"}
      </Button>

      {/* Announced on change; empty while idle so it stays quiet. */}
      <span role="status" aria-live="polite" className="sr-only">
        {state === "copied"
          ? `${label} copied to clipboard`
          : state === "failed"
            ? `Could not copy ${label}. Select the text to copy it manually.`
            : ""}
      </span>
    </>
  );
}
