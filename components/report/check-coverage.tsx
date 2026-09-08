import { SCORE_AXES } from "@/lib/scanner/score";
import { cn } from "@/lib/cn";
import { CHECK_IDS, type CheckResult, type CheckStatus } from "@/lib/scanner/types";

const STATUS_LABEL: Record<CheckStatus, string> = {
  ok: "Ran",
  error: "Unavailable",
  not_configured: "Not configured",
};

const STATUS_TONE: Record<CheckStatus, string> = {
  ok: "border-pass-edge text-pass",
  error: "border-medium-edge text-medium",
  not_configured: "border-border-strong text-fg-subtle",
};

/** Colour-independent glyph, so status survives greyscale like severity does. */
const STATUS_GLYPH: Record<CheckStatus, string> = {
  ok: "✓",
  error: "!",
  not_configured: "–",
};

interface CheckCoverageProps {
  checks: readonly CheckResult[];
}

/**
 * Six cells, one per check: did it run, and if not, why.
 *
 * Honesty about coverage is part of the product. A report that quietly omits
 * a check it could not perform looks identical to one where everything passed,
 * and those are very different reports.
 */
export function CheckCoverage({ checks }: CheckCoverageProps) {
  return (
    <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      {CHECK_IDS.map((id) => {
        const result = checks.find((candidate) => candidate.check === id);
        const status: CheckStatus = result?.status ?? "error";
        const label = SCORE_AXES.find((axis) => axis.check === id)?.label ?? id;

        return (
          <li
            key={id}
            className={cn(
              "rounded-md border bg-surface px-3 py-2.5",
              STATUS_TONE[status],
            )}
          >
            <div className="flex items-baseline justify-between gap-2">
              <span className="label text-fg">{label}</span>
              <span aria-hidden="true" className="font-mono text-xs">
                {STATUS_GLYPH[status]}
              </span>
            </div>

            <p className="label mt-1">{STATUS_LABEL[status]}</p>

            {/* The reason is the entire point of this strip when a check did
                not run, so it is shown rather than hidden behind a tooltip. */}
            {result?.reason ? (
              <p className="mt-1.5 text-2xs leading-relaxed text-fg-muted">
                {result.reason}
              </p>
            ) : (
              <p className="mt-1.5 font-mono text-2xs tabular-nums text-fg-subtle">
                {result ? `${result.findings.length} findings · ${result.durationMs}ms` : ""}
              </p>
            )}
          </li>
        );
      })}
    </ul>
  );
}
