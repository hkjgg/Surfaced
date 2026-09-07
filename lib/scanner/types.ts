/**
 * Every shared type in the scanner. Nothing else declares these; each module
 * imports from here so a change to the report shape is a single edit.
 */

import type { Severity } from "@/lib/severity";

export type { Severity };

/** The six checks, in report order. */
export const CHECK_IDS = [
  "email-auth",
  "dns",
  "headers",
  "tls",
  "ct",
  "exposure",
] as const;

export type CheckId = (typeof CHECK_IDS)[number];

/**
 * Check outcome states.
 *
 * `error` and `not_configured` are deliberately distinct from `ok`. A check
 * that could not run is not a check that passed, and score.ts excludes both
 * from the denominator rather than guessing in the domain's favour.
 */
export type CheckStatus = "ok" | "error" | "not_configured";

/**
 * A copy-ready fix. Whatever is present must be literal and correct for the
 * domain that was actually scanned — never a placeholder.
 */
export interface Remediation {
  /** One-line instruction in plain language. */
  readonly summary: string;
  /** A DNS record to publish, already filled in for this domain. */
  readonly dnsRecord?: {
    readonly name: string;
    readonly type: "TXT" | "MX" | "CAA" | "DS";
    readonly value: string;
  };
  /** An exact HTTP response header line to send. */
  readonly headerLine?: string;
  /** Optional reference (RFC, spec, or vendor doc). */
  readonly reference?: string;
}

export interface Finding {
  /** Stable machine id, e.g. "dmarc.missing". Safe to use as a React key. */
  readonly id: string;
  readonly check: CheckId;
  readonly severity: Severity;
  /** Short human title. */
  readonly title: string;
  /** What the scanner actually observed. Facts only, no interpretation. */
  readonly observed: string;
  /** Why that matters — the consequence, in plain language. */
  readonly impact: string;
  /** Absent only for `pass` findings, which need no fix. */
  readonly remediation?: Remediation;
}

/**
 * The result of one check.
 *
 * `data` is the check's own structured evidence — the parsed records behind
 * the findings — so a report can show its working rather than asking the
 * reader to trust the verdict.
 */
export interface CheckResult<TData = unknown> {
  readonly check: CheckId;
  readonly status: CheckStatus;
  /** Present when status is "error" or "not_configured". */
  readonly reason?: string;
  readonly findings: readonly Finding[];
  readonly data?: TData;
  readonly durationMs: number;
}

export interface ScanScore {
  /** 0–100, or null when no check produced a scoreable result. */
  readonly value: number | null;
  /** Checks that contributed to the denominator. */
  readonly checksIncluded: readonly CheckId[];
  /** Checks left out because they errored or were not configured. */
  readonly checksExcluded: readonly CheckId[];
  /**
   * True when any check was excluded — the score is then a partial view and
   * must be labelled as such wherever it is displayed.
   */
  readonly partial: boolean;
}

export interface ScanReport {
  /** The validated, normalised hostname that was actually scanned. */
  readonly hostname: string;
  /** ISO 8601, when the scan started. */
  readonly scannedAt: string;
  readonly durationMs: number;
  readonly score: ScanScore;
  /** Every finding across all checks, most severe first. */
  readonly findings: readonly Finding[];
  readonly checks: readonly CheckResult[];
}
