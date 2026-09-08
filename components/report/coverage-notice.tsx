import { Callout } from "@/components/ui";
import { SCORE_AXES } from "@/lib/scanner/score";
import { CHECK_IDS, type CheckId, type CheckResult, type ScanScore } from "@/lib/scanner/types";

function axisLabel(check: CheckId): string {
  return SCORE_AXES.find((axis) => axis.check === check)?.label ?? check;
}

interface CoverageNoticeProps {
  score: ScanScore;
  checks: readonly CheckResult[];
}

/**
 * What was NOT checked, and why.
 *
 * This sits directly under the score, above the findings, because it is a
 * caveat on the number rather than a footnote to the report. A 92 from five
 * checks is not a 92 from six, and the difference has to be visible at the
 * moment someone reads the 92 — not further down the page where they may
 * never scroll.
 *
 * The reason is printed verbatim from the check. "crt.sh timed out" and "no
 * HIBP key is configured" are different facts and the reader deserves to know
 * which one they got.
 */
export function CoverageNotice({ score, checks }: CoverageNoticeProps) {
  if (!score.partial) return null;

  const excluded = score.checksExcluded.map((check) => ({
    check,
    label: axisLabel(check),
    result: checks.find((candidate) => candidate.check === check),
  }));

  return (
    <Callout tone="warn" title="Partial score">
      <p>
        This score covers {score.checksIncluded.length} of {CHECK_IDS.length}{" "}
        checks. {excluded.length === 1 ? "One check" : `${excluded.length} checks`}{" "}
        could not be completed, and{" "}
        {excluded.length === 1 ? "it is" : "they are"} excluded rather than
        counted as passing or failing.
      </p>

      <ul className="mt-2 flex flex-col gap-1.5">
        {excluded.map(({ check, label, result }) => (
          <li key={check} className="text-xs">
            <span className="label text-fg">{label}</span>
            <span className="text-fg-subtle"> · </span>
            <span className="text-fg-muted">
              {result?.reason ??
                "The check returned no result and no reason was recorded."}
            </span>
          </li>
        ))}
      </ul>
    </Callout>
  );
}
