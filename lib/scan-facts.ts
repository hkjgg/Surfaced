/**
 * Facts about the scanner that the marketing surface is allowed to state.
 *
 * The rule that governs this file is the same one that governs the report: do
 * not claim anything you have not measured. A landing page that promises
 * "results in under a second" and then takes twelve is contradicted by the
 * product itself, in front of the person you just made the promise to.
 *
 * So each value here is either derived from code, or carries a note saying
 * where the number came from. Nothing is rounded down for effect.
 */

import { CHECK_IDS } from "@/lib/scanner/types";

/** Derived, so it cannot drift from the engine. */
export const CHECK_COUNT = CHECK_IDS.length;

/**
 * Observed end-to-end scan duration.
 *
 * Source: operator measurement on a network with unrestricted egress,
 * 2026-09. The upper figure is a real observation, not the timeout — slow
 * Certificate Transparency lookups dominate it.
 *
 * The engine's own hard ceiling is TOTAL_TIMEOUT_MS in
 * lib/scanner/orchestrate.ts, currently 20s, with per-check budgets of 8s
 * (12s for CT). A scan cannot exceed that regardless of what this says, so if
 * these figures ever look optimistic the ceiling is the honest fallback.
 *
 * If you change the checks or their timeouts, re-measure rather than editing
 * this to match a hunch.
 */
export const SCAN_DURATION_LABEL = "0.6–12s typical";

/**
 * Specifications the checks actually implement, for the telemetry strip.
 *
 * Each is cited in the findings the corresponding module emits — grep the
 * `reference` fields in email-auth.ts and headers.ts before adding to this
 * list. An RFC number on a landing page that the code does not implement is
 * the same class of lie as a fabricated latency.
 */
export const IMPLEMENTED_RFCS = ["7208", "6797", "6376"] as const;
