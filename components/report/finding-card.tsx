"use client";

import { useId, useState } from "react";

import { RemediationBlock } from "@/components/report/remediation-tabs";
import { Badge } from "@/components/ui";
import { cn } from "@/lib/cn";
import type { Finding } from "@/lib/scanner/types";

interface FindingCardProps {
  finding: Finding;
  /** Position in the list, for the stagger. */
  index: number;
}

/** Cap the stagger so a 30-finding report does not take a second to settle. */
const STAGGER_MS = 30;
const MAX_STAGGER_STEPS = 12;

/**
 * One finding: what was observed, and why it matters.
 *
 * Collapsed to the observed line by default — that is the fact — with impact
 * and the fix behind a disclosure. Severity is carried by the Badge, which
 * renders the rank meter alongside the label, so it survives greyscale.
 */
export function FindingCard({ finding, index }: FindingCardProps) {
  const [open, setOpen] = useState(false);
  const panelId = useId();

  const delay = Math.min(index, MAX_STAGGER_STEPS) * STAGGER_MS;

  return (
    <li
      className="animate-rise rounded-lg border border-border bg-surface shadow-1"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="flex flex-wrap items-start gap-x-3 gap-y-2 px-4 py-3">
        <Badge variant={finding.severity} className="mt-0.5 shrink-0" />

        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-medium text-fg">{finding.title}</h3>
          <p className="mt-1 text-xs break-words text-fg-muted" data-mono>
            {finding.observed}
          </p>
        </div>

        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          aria-controls={panelId}
          className={cn(
            "label shrink-0 rounded-sm px-2 py-1 text-fg-subtle transition-colors duration-150",
            "hover:bg-raised hover:text-fg-muted",
          )}
        >
          {open ? "Less" : "Why"}
        </button>
      </div>

      {/* Rendered only when open, so collapsed content is not reachable by tab
          or read out by a screen reader walking the page. */}
      {open ? (
        <div id={panelId} className="border-t border-border px-4 py-3">
          <p className="text-xs text-fg-muted">{finding.impact}</p>

          {finding.remediation ? (
            <RemediationBlock
              remediation={finding.remediation}
              findingTitle={finding.title}
            />
          ) : null}
        </div>
      ) : null}
    </li>
  );
}
