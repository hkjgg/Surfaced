"use client";

import { useId, useRef, useState } from "react";

import { CopyButton } from "@/components/report/copy-button";
import { cn } from "@/lib/cn";
import { remediationTargets } from "@/lib/scanner/remediation";
import type { Remediation } from "@/lib/scanner/types";

interface RemediationBlockProps {
  remediation: Remediation;
  /** Used in copy-button labels so the announcement says what was copied. */
  findingTitle: string;
}

/**
 * The fix, in whichever deployment forms apply.
 *
 * Tabs appear only when there is genuinely more than one form. A DNS fix has
 * exactly one representation, so it renders as a plain block — a one-tab tab
 * strip is furniture, not navigation.
 *
 * Some remediations have no snippet at all ("renew the certificate", "add a
 * second nameserver"). Those show the summary and nothing else. See
 * lib/scanner/remediation.ts for why inventing one would be worse.
 */
export function RemediationBlock({ remediation, findingTitle }: RemediationBlockProps) {
  const targets = remediationTargets(remediation);
  const [active, setActive] = useState(0);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const baseId = useId();

  const current = targets[active] ?? targets[0];

  // Roving focus: arrows move between tabs, Home/End jump to the ends. This is
  // the expected behaviour for a tablist and costs very little to get right.
  function handleKeyDown(event: React.KeyboardEvent<HTMLButtonElement>) {
    const lastIndex = targets.length - 1;
    let next: number | null = null;

    if (event.key === "ArrowRight") next = active === lastIndex ? 0 : active + 1;
    if (event.key === "ArrowLeft") next = active === 0 ? lastIndex : active - 1;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = lastIndex;

    if (next === null) return;

    event.preventDefault();
    setActive(next);
    tabRefs.current[next]?.focus();
  }

  return (
    <div className="mt-3 rounded-md border border-border bg-bg">
      <p className="border-b border-border px-3 py-2 text-xs text-fg-muted">
        {remediation.summary}
      </p>

      {targets.length > 0 && current ? (
        <div>
          {targets.length > 1 ? (
            <div
              role="tablist"
              aria-label={`Deployment options for ${findingTitle}`}
              className="flex gap-1 overflow-x-auto border-b border-border px-2 py-1.5"
            >
              {targets.map((target, index) => (
                <button
                  key={target.id}
                  ref={(node) => {
                    tabRefs.current[index] = node;
                  }}
                  type="button"
                  role="tab"
                  id={`${baseId}-tab-${target.id}`}
                  aria-selected={index === active}
                  aria-controls={`${baseId}-panel-${target.id}`}
                  tabIndex={index === active ? 0 : -1}
                  onClick={() => setActive(index)}
                  onKeyDown={handleKeyDown}
                  className={cn(
                    "label shrink-0 rounded-sm px-2 py-1 transition-colors duration-150",
                    index === active
                      ? "bg-accent-wash text-accent"
                      : "text-fg-subtle hover:bg-raised hover:text-fg-muted",
                  )}
                >
                  {target.label}
                </button>
              ))}
            </div>
          ) : null}

          <div
            role={targets.length > 1 ? "tabpanel" : undefined}
            id={`${baseId}-panel-${current.id}`}
            aria-labelledby={
              targets.length > 1 ? `${baseId}-tab-${current.id}` : undefined
            }
            className="p-3"
          >
            <div className="flex items-start gap-2">
              <pre className="min-w-0 flex-1 overflow-x-auto rounded-sm bg-raised px-2.5 py-2 text-2xs leading-relaxed text-fg">
                <code>{current.code}</code>
              </pre>
              <CopyButton
                value={current.code}
                label={`${current.label} fix for ${findingTitle}`}
              />
            </div>

            <p className="mt-2 text-2xs text-fg-subtle">{current.note}</p>
          </div>
        </div>
      ) : null}

      {remediation.reference ? (
        <p className="border-t border-border px-3 py-2 text-2xs text-fg-subtle">
          Reference:{" "}
          {remediation.reference.startsWith("http") ? (
            <a
              href={remediation.reference}
              target="_blank"
              rel="noreferrer noopener"
              className="text-accent underline underline-offset-2"
            >
              {remediation.reference}
            </a>
          ) : (
            <span data-mono>{remediation.reference}</span>
          )}
        </p>
      ) : null}
    </div>
  );
}
