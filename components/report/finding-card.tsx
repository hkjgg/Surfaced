"use client";

import { useId, useState } from "react";

import { RemediationBlock } from "@/components/report/remediation-tabs";
import { TONE_BORDER, tierFor, type FindingTier } from "@/components/report/tone";
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
 * Surface and border weight per tier.
 *
 * A critical finding sits on a lighter surface with a coloured left edge; a
 * pass recedes. Severity itself is still carried by the Badge's rank meter and
 * uppercase label in every tier, so this is emphasis, not information — strip
 * the colour and the report reads exactly the same.
 */
const TIER_SURFACE: Record<FindingTier, string> = {
  loud: "border-l-2 bg-raised shadow-2",
  flat: "bg-surface shadow-1",
  quiet: "bg-surface/60 shadow-none",
};

const TIER_TITLE: Record<FindingTier, string> = {
  loud: "text-fg",
  flat: "text-fg",
  quiet: "text-fg-muted",
};

/**
 * One finding: what was observed, and why it matters.
 *
 * Collapsed to the observed line by default — that is the fact — with impact
 * and the fix behind a disclosure.
 */
export function FindingCard({ finding, index }: FindingCardProps) {
  const [open, setOpen] = useState(false);
  const panelId = useId();

  const tier = tierFor(finding.severity);
  const delay = Math.min(index, MAX_STAGGER_STEPS) * STAGGER_MS;

  return (
    <li
      className={cn(
        "animate-rise rounded-lg border border-border",
        TIER_SURFACE[tier],
        tier === "loud" && TONE_BORDER[finding.severity],
      )}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="flex flex-wrap items-start gap-x-3 gap-y-2 px-4 py-3">
        <Badge variant={finding.severity} className="mt-0.5 shrink-0" />

        <div className="min-w-0 flex-1">
          <h3 className={cn("text-sm font-medium", TIER_TITLE[tier])}>
            {finding.title}
          </h3>
          <p
            className={cn(
              "mt-1 text-xs break-words",
              tier === "quiet" ? "text-fg-subtle" : "text-fg-muted",
            )}
            data-mono
          >
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
