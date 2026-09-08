"use client";

import type { FindingFilterControls } from "@/components/report/use-finding-filters";
import { cn } from "@/lib/cn";
import type { Finding } from "@/lib/scanner/types";
import { SEVERITIES, SEVERITY, type Severity } from "@/lib/severity";

const ACTIVE_TONE: Record<Severity, string> = {
  critical: "border-critical-edge bg-critical-wash text-critical",
  high: "border-high-edge bg-high-wash text-high",
  medium: "border-medium-edge bg-medium-wash text-medium",
  low: "border-low-edge bg-low-wash text-low",
  pass: "border-pass-edge bg-pass-wash text-pass",
};

interface FilterBarProps {
  findings: readonly Finding[];
  /** How many are showing after filtering, for the live announcement. */
  visibleCount: number;
  filters: FindingFilterControls;
}

/**
 * Counts and triage controls.
 *
 * Counts are totals from the whole report, not from the filtered view — they
 * are how you decide what to filter TO, so they must not move as you filter.
 *
 * Every control is a real button with `aria-pressed`. Severity is never
 * carried by colour alone here either: each button shows the rank meter and
 * the label, exactly as the badges do.
 */
export function FilterBar({ findings, visibleCount, filters }: FilterBarProps) {
  const counts = SEVERITIES.map((severity) => ({
    severity,
    count: findings.filter((finding) => finding.severity === severity).length,
  }));

  const selected = filters.severities;

  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-2.5 shadow-1">
      <div className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          onClick={filters.clear}
          aria-pressed={!filters.isFiltered}
          className={cn(
            "label rounded-sm border px-2 py-1 transition-colors duration-150",
            filters.isFiltered
              ? "border-border text-fg-subtle hover:bg-raised hover:text-fg-muted"
              : "border-accent-edge bg-accent-wash text-accent",
          )}
        >
          All {findings.length}
        </button>

        {counts.map(({ severity, count }) => {
          const active = selected?.includes(severity) ?? false;
          // A severity with no findings is still shown, greyed and disabled:
          // "Critical 0" is information, and hiding it would make the absence
          // of a control look like the absence of a check.
          const empty = count === 0;

          return (
            <button
              key={severity}
              type="button"
              disabled={empty}
              onClick={() => filters.toggleSeverity(severity)}
              aria-pressed={active}
              className={cn(
                "label inline-flex items-center gap-1.5 rounded-sm border px-2 py-1 transition-colors duration-150",
                active
                  ? ACTIVE_TONE[severity]
                  : "border-border text-fg-subtle hover:bg-raised hover:text-fg-muted",
                empty && "opacity-45",
              )}
            >
              <span aria-hidden="true" className="tracking-normal">
                {SEVERITY[severity].meter}
              </span>
              <span>
                {SEVERITY[severity].label} {count}
              </span>
            </button>
          );
        })}

        <label className="ml-auto flex cursor-pointer items-center gap-2 rounded-sm px-1 py-1">
          <input
            type="checkbox"
            checked={filters.hidePassed}
            onChange={(event) => filters.setHidePassed(event.target.checked)}
            className="h-3.5 w-3.5 accent-[var(--color-accent)]"
          />
          <span className="label text-fg-subtle">Hide passed</span>
        </label>
      </div>

      <p role="status" aria-live="polite" className="sr-only">
        Showing {visibleCount} of {findings.length} findings.
      </p>
    </div>
  );
}
