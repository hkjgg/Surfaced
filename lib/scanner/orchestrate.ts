/**
 * Runs the six checks and assembles the report.
 *
 * Every check is independent and failure-isolated: one that throws or times
 * out becomes an `error` result and the scan still returns. A partial report
 * with four solid sections is useful; a 500 because crt.sh was slow is not.
 *
 * Two entry points, one implementation. `scanHostnameStream` emits an event
 * the moment each check settles; `scanHostname` drains that stream and returns
 * the finished report. There is deliberately no second code path — if the two
 * could diverge, the live log and the report would eventually disagree about
 * what happened.
 */

import { checkCt } from "./ct";
import { checkDns } from "./dns";
import { checkEmailAuth } from "./email-auth";
import { checkExposure } from "./exposure";
import { checkHeaders } from "./headers";
import { checkTls } from "./tls";
import { collectFindings, scoreReport } from "./score";
import { deadlineSignal } from "./internal/timeout";
import {
  CHECK_IDS,
  type CheckId,
  type CheckResult,
  type CheckStatus,
  type ScanReport,
} from "./types";

/** Per-check wall-time budget. */
const DEFAULT_CHECK_TIMEOUT_MS = 8_000;
/**
 * crt.sh is routinely the slowest dependency and intermittently returns 502,
 * so it gets the most room — and ct.ts spends this same budget across its one
 * retry rather than being granted extra. TOTAL_TIMEOUT_MS still caps it.
 */
const CT_TIMEOUT_MS = 20_000;
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

/** Emitted once, before any check has settled. */
export interface ScanStartEvent {
  readonly type: "start";
  readonly hostname: string;
  readonly scannedAt: string;
  /** Every check that will report, in report order. Lets a client reserve space. */
  readonly checks: readonly CheckId[];
  /** True when the report is being replayed from cache rather than measured now. */
  readonly cached: boolean;
}

/**
 * Emitted the instant one check settles.
 *
 * `durationMs` is that check's own wall time; `elapsedMs` is time since the
 * scan began. Both are measured, never simulated — nothing in this file paces
 * output with a timer.
 *
 * `elapsedMs` is absent on a cached replay. The checks did run and their
 * durations are real, but they did not run *now*, and stamping this scan's
 * clock onto them would be inventing a measurement.
 */
export interface ScanCheckEvent {
  readonly type: "check";
  readonly check: CheckId;
  readonly status: CheckStatus;
  readonly findingCount: number;
  readonly durationMs: number;
  readonly elapsedMs?: number;
  readonly reason?: string;
}

/** Emitted last, carrying the complete report. */
export interface ScanReportEvent {
  readonly type: "report";
  readonly report: ScanReport;
}

export type ScanEvent = ScanStartEvent | ScanCheckEvent | ScanReportEvent;

/** Run one check, converting any throw into an `error` result. */
async function runCheck(
  definition: (typeof CHECKS)[number],
  hostname: string,
  parentSignal: AbortSignal,
): Promise<CheckResult> {
  const perCheck = deadlineSignal(definition.timeoutMs, parentSignal);
  const started = Date.now();

  try {
    return await definition.run(hostname, perCheck.signal);
  } catch (error) {
    // Failure is a normal outcome here, not an exception to propagate.
    return {
      check: definition.id,
      status: "error",
      reason: describeError(error),
      findings: [],
      durationMs: Date.now() - started,
    };
  } finally {
    perCheck.cancel();
  }
}

/** Report order, not completion order, so the report shape is stable. */
function inReportOrder(results: readonly CheckResult[]): CheckResult[] {
  return CHECK_IDS.flatMap((id) => results.filter((result) => result.check === id));
}

function assembleReport(
  hostname: string,
  scannedAt: string,
  startedAt: number,
  results: readonly CheckResult[],
): ScanReport {
  const checks = inReportOrder(results);

  return {
    hostname,
    scannedAt,
    durationMs: Date.now() - startedAt,
    score: scoreReport(checks),
    findings: collectFindings(checks),
    checks,
  };
}

/**
 * Scan a hostname, yielding an event as each check settles.
 *
 * The hostname must ALREADY have passed validate.ts; this does not re-validate.
 *
 * The loop below waits on a promise that a settling check resolves. That is
 * what makes the output honest: a line appears because a check finished, not
 * because a timer fired. Two checks that settle 4ms apart produce two events
 * 4ms apart.
 */
export async function* scanHostnameStream(
  hostname: string,
  options: ScanOptions = {},
): AsyncGenerator<ScanEvent, void, void> {
  const startedAt = Date.now();
  const scannedAt = new Date(startedAt).toISOString();

  const overall = deadlineSignal(
    options.totalTimeoutMs ?? TOTAL_TIMEOUT_MS,
    options.signal,
  );

  try {
    yield {
      type: "start",
      hostname,
      scannedAt,
      checks: CHECKS.map((definition) => definition.id),
      cached: false,
    };

    /** Settled results not yet yielded. */
    const pending: CheckResult[] = [];
    /** Resolved by whichever check settles next, waking the drain loop. */
    let wake: (() => void) | null = null;

    const running = CHECKS.map(async (definition) => {
      const result = await runCheck(definition, hostname, overall.signal);
      pending.push(result);
      wake?.();
      wake = null;
      return result;
    });

    // runCheck never rejects, so this only exists to keep the promises tracked
    // and to surface a defensive failure if that invariant is ever broken.
    const settled = Promise.allSettled(running);

    const results: CheckResult[] = [];

    while (results.length < CHECKS.length) {
      if (pending.length === 0) {
        await new Promise<void>((resolve) => {
          wake = resolve;
        });
        continue;
      }

      const result = pending.shift();
      if (!result) continue;

      results.push(result);

      yield {
        type: "check",
        check: result.check,
        status: result.status,
        findingCount: result.findings.length,
        durationMs: result.durationMs,
        elapsedMs: Date.now() - startedAt,
        ...(result.reason === undefined ? {} : { reason: result.reason }),
      };
    }

    await settled;

    yield {
      type: "report",
      report: assembleReport(hostname, scannedAt, startedAt, results),
    };
  } finally {
    overall.cancel();
  }
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
  for await (const event of scanHostnameStream(hostname, options)) {
    if (event.type === "report") return event.report;
  }

  // Unreachable: the generator always yields a report before completing.
  throw new Error("The scan produced no report");
}

/**
 * The events a cached report would have produced, for replaying to a streaming
 * client.
 *
 * The durations are the ones measured when the scan actually ran, and `cached`
 * is set on the start event so the UI can say so rather than implying it just
 * timed those checks.
 */
export function replayEvents(report: ScanReport): ScanEvent[] {
  const events: ScanEvent[] = [
    {
      type: "start",
      hostname: report.hostname,
      scannedAt: report.scannedAt,
      checks: CHECK_IDS,
      cached: true,
    },
  ];

  for (const check of report.checks) {
    events.push({
      type: "check",
      check: check.check,
      status: check.status,
      findingCount: check.findings.length,
      durationMs: check.durationMs,
      ...(check.reason === undefined ? {} : { reason: check.reason }),
    });
  }

  events.push({ type: "report", report });
  return events;
}
