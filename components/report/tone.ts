import type { Severity } from "@/lib/severity";

/**
 * Severity → Tailwind class, in one place.
 *
 * Three components were carrying near-identical copies of this map. They are
 * the kind of thing that drifts silently: one gets a new variant, another does
 * not, and the report ends up showing two different oranges for "high".
 *
 * These are class names only. The colour values themselves live in
 * app/globals.css, and nothing here introduces a new one.
 *
 * Colour is always the SECONDARY channel — every consumer of these maps also
 * renders the rank meter and the uppercase label. See CLAUDE.md §5.
 */

/** Foreground: severity as text or as an SVG stroke via currentColor. */
export const TONE_TEXT: Readonly<Record<Severity, string>> = Object.freeze({
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  pass: "text-pass",
});

/** Border colour, for the weighted left edge on a serious finding. */
export const TONE_BORDER: Readonly<Record<Severity, string>> = Object.freeze({
  critical: "border-l-critical",
  high: "border-l-high",
  medium: "border-l-medium",
  low: "border-l-low",
  pass: "border-l-pass",
});

/** Solid fill, for the coverage grid's status dots. */
export const TONE_DOT: Readonly<Record<Severity, string>> = Object.freeze({
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  pass: "bg-pass",
});

/** Wash fill plus edge, for a selected filter chip. */
export const TONE_CHIP: Readonly<Record<Severity, string>> = Object.freeze({
  critical: "border-critical-edge bg-critical-wash text-critical",
  high: "border-high-edge bg-high-wash text-high",
  medium: "border-medium-edge bg-medium-wash text-medium",
  low: "border-low-edge bg-low-wash text-low",
  pass: "border-pass-edge bg-pass-wash text-pass",
});

/**
 * How much visual weight a finding gets.
 *
 * The point of the tiers is that a critical finding should not have to compete
 * with fourteen passes for attention. The Badge is identical in every tier, so
 * dropping the colour changes nothing about whether severity is legible — the
 * weighting is reinforcement, never the message.
 */
export type FindingTier = "loud" | "flat" | "quiet";

export function tierFor(severity: Severity): FindingTier {
  if (severity === "critical" || severity === "high") return "loud";
  if (severity === "pass") return "quiet";
  return "flat";
}
