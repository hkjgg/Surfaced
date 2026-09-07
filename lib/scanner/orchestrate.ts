/**
 * Runs the six checks and assembles the report.
 *
 * Every check is independent and failure-isolated: one that throws or times
 * out becomes an `error` result and the scan still returns. A partial report
 * with four solid sections is useful; a 500 because crt.sh was slow is not.
 */

import { checkCt } from "./ct";
import { checkDns } from "./dns";
import { checkEmailAuth } from "./email-auth";
import { checkExposure } from "./exposure";
import { checkHeaders } from "./headers";
import { checkTls } from "./tls";
import { collectFindings, scoreReport } from "./score";
import { deadlineSignal } from "./internal/timeout";
import type { CheckId, CheckResult, ScanReport } from "./types";

/** Per-check wall-time budget. */
const DEFAULT_CHECK_TIMEOUT_MS = 8_000;
/** crt.sh is routinely the slowest dependency, so it gets more room. */
const CT_TIMEOUT_MS = 12_000;
/** Hard ceiling for the whole scan, regardless of individual budgets. */
const TOTAL_TIMEOUT_MS = 20_000;

type CheckFn = (hostname: string, signal: AbortSignal) => Promise<CheckResult>;

const CHECKS: ReadonlyArray<{
  readonly id: CheckId;
  readonly run: CheckFn;
  readonly timeoutMs: number;
}> = [
  { id: "email-auth", run: checkEmailAuth, timeoutMs: DEFAULT_CHECK_TIMEOUT_MS },
  { id: "dns", run: checkDns, timeoutMs: DEFAULT_CHECK_TIMEOUT_MS },
  { id: "headers", run: checkHeaders, timeoutMs: DEFAULT_CHECK_TIMEOUT_MS },
  { id: "tls", run: checkTls, timeoutMs: DEFAULT_CHECK_TIMEOUT_MS },
  { id: "ct", run: checkCt, timeoutMs: CT_TIMEOUT_MS },
  { id: "exposure", run: checkExposure, timeoutMs: DEFAULT_CHECK_TIMEOUT_MS },
];

function describeError(error: unknown): string {
  if (error instanceof Error) {
    // Node nests the useful detail in `cause` for fetch failures.
    const cause = (error as { cause?: unknown }).cause;
    if (cause instanceof Error && cause.message !== error.message) {
      return `${error.message} (${cause.message})`;
    }
    return error.message;
  }
  return "The check failed for an unknown reason";
}

export interface ScanOptions {
  /** Overall budget. Individual checks are still capped by their own timeout. */
  readonly totalTimeoutMs?: number;
  /** Caller-controlled cancellation, e.g. the request being aborted. */
  readonly signal?: AbortSignal;
}

/**
 * Scan a hostname that has ALREADY passed validate.ts.
 *
 * This function does not re-validate; the API route owns that boundary. Do
 * not call it with unvalidated input.
 */
export async function scanHostname(
  hostname: string,
  options: ScanOptions = {},
): Promise<ScanReport> {
  const started = Date.now();
  const scannedAt = new Date(started).toISOString();

  const overall = deadlineSignal(
    options.totalTimeoutMs ?? TOTAL_TIMEOUT_MS,
    options.signal,
  );

  try {
    const settled = await Promise.allSettled(
      CHECKS.map(async ({ id, run, timeoutMs }) => {
        const perCheck = deadlineSignal(timeoutMs, overall.signal);
        const checkStarted = Date.now();

        try {
          return await run(hostname, perCheck.signal);
        } catch (error) {
          // Failure is a normal outcome here, not an exception to propagate.
          const result: CheckResult = {
            check: id,
            status: "error",
            reason: describeError(error),
            findings: [],
            durationMs: Date.now() - checkStarted,
          };
          return result;
        } finally {
          perCheck.cancel();
        }
      }),
    );

    const checks: CheckResult[] = settled.map((outcome, index) => {
      if (outcome.status === "fulfilled") return outcome.value;

      // Defensive: the inner catch should already have handled this.
      const definition = CHECKS[index];
      return {
        check: definition?.id ?? "dns",
        status: "error",
        reason: describeError(outcome.reason),
        findings: [],
        durationMs: 0,
      };
    });

    return {
      hostname,
      scannedAt,
      durationMs: Date.now() - started,
      score: scoreReport(checks),
      findings: collectFindings(checks),
      checks,
    };
  } finally {
    overall.cancel();
  }
}
