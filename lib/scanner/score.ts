/**
 * Scoring.
 *
 * Deductions from 100, weighted per check. Every tunable lives in the two
 * constants below so the model can be adjusted in one place rather than
 * chased through the checks.
 */

import { compareSeverity, type Severity } from "@/lib/severity";
import { CHECK_IDS, type CheckId, type CheckResult, type Finding, type ScanScore } from "./types";

/**
 * How much of the score each check can consume.
 *
 * These are relative weights, not percentages — the denominator is the sum of
 * whichever checks actually ran, so the numbers stay meaningful when a check
 * is excluded. Email authentication and transport security carry the most
 * because they are the two areas where a misconfiguration directly enables
 * impersonation or interception. Certificate Transparency carries least
 * because its findings are reconnaissance signals about already-public data,
 * not defects.
 */
export const CHECK_WEIGHTS: Readonly<Record<CheckId, number>> = Object.freeze({
  "email-auth": 25,
  dns: 15,
  headers: 20,
  tls: 25,
  ct: 5,
  exposure: 10,
});

/**
 * Deduction per finding, as a fraction of its check's weight.
 *
 * A single critical finding consumes its check's entire weight; that is
 * deliberate, since a critical finding in one area is not offset by tidiness
 * elsewhere within the same area.
 */
export const SEVERITY_DEDUCTION: Readonly<Record<Severity, number>> = Object.freeze({
  critical: 1.0,
  high: 0.5,
  medium: 0.25,
  low: 0.08,
  pass: 0,
});

/**
 * A check counts toward the denominator only when it produced a real result.
 *
 * This is the important decision in this module. A check that timed out, or
 * that was never configured, is EXCLUDED rather than scored:
 *
 *   - Scoring it as a pass would flatter a domain for a check that never ran,
 *     which is how a scanner ends up lying by omission.
 *   - Scoring it as a failure would punish a domain because crt.sh was down,
 *     which is not a fact about the domain at all.
 *
 * The excluded checks are reported alongside the score, and `partial` is set,
 * so a 92 out of four checks can never be mistaken for a 92 out of six.
 */
function isScoreable(result: CheckResult): boolean {
  return result.status === "ok";
}

export function scoreReport(results: readonly CheckResult[]): ScanScore {
  const included: CheckId[] = [];
  const excluded: CheckId[] = [];

  let totalWeight = 0;
  let totalDeduction = 0;

  for (const checkId of CHECK_IDS) {
    const result = results.find((candidate) => candidate.check === checkId);

    if (!result || !isScoreable(result)) {
      excluded.push(checkId);
      continue;
    }

    included.push(checkId);

    const weight = CHECK_WEIGHTS[checkId];
    totalWeight += weight;

    const rawDeduction = result.findings.reduce(
      (sum, finding) => sum + SEVERITY_DEDUCTION[finding.severity] * weight,
      0,
    );

    // Cap per check so one very broken area cannot drive the total negative
    // or swamp every other signal in the report.
    totalDeduction += Math.min(rawDeduction, weight);
  }

  if (totalWeight === 0) {
    return {
      value: null,
      checksIncluded: included,
      checksExcluded: excluded,
      partial: true,
    };
  }

  const value = Math.max(
    0,
    Math.min(100, Math.round(100 * (1 - totalDeduction / totalWeight))),
  );

  return {
    value,
    checksIncluded: included,
    checksExcluded: excluded,
    partial: excluded.length > 0,
  };
}

/** All findings across all checks, most severe first, stable within a rank. */
export function collectFindings(results: readonly CheckResult[]): Finding[] {
  return results
    .flatMap((result) => [...result.findings])
    .sort((a, b) => compareSeverity(a.severity, b.severity));
}
