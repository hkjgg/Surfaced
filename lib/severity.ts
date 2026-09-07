/**
 * The severity scale.
 *
 * Colour is the SECONDARY channel here. The primary channel is the rank meter
 * plus the uppercase label, so a finding's severity survives greyscale
 * printing, a monochrome display, and any colour-vision deficiency. Never
 * render severity as a bare colour swatch.
 *
 * `pass` is part of the scale on purpose: a report that only lists problems
 * gives no evidence that anything was actually checked.
 */

export const SEVERITIES = ["critical", "high", "medium", "low", "pass"] as const;

export type Severity = (typeof SEVERITIES)[number];

export interface SeverityMeta {
  /** Uppercase label. Always rendered — never rely on the colour alone. */
  readonly label: string;
  /** Colour-independent rank glyph, readable in greyscale. */
  readonly meter: string;
  /** Sort weight, highest first. */
  readonly rank: number;
  /** Plain-language meaning, for tooltips and the eventual report legend. */
  readonly meaning: string;
}

export const SEVERITY: Readonly<Record<Severity, SeverityMeta>> = Object.freeze({
  critical: {
    label: "Critical",
    meter: "▮▮▮▮",
    rank: 4,
    meaning: "Exploitable or actively harmful. Fix before anything else.",
  },
  high: {
    label: "High",
    meter: "▮▮▮▯",
    rank: 3,
    meaning: "A real weakness with a clear path to harm. Fix soon.",
  },
  medium: {
    label: "Medium",
    meter: "▮▮▯▯",
    rank: 2,
    meaning: "Weakens defence in depth. Worth scheduling.",
  },
  low: {
    label: "Low",
    meter: "▮▯▯▯",
    rank: 1,
    meaning: "Minor hardening opportunity or informational.",
  },
  pass: {
    label: "Pass",
    meter: "✓",
    rank: 0,
    meaning: "Checked, and configured correctly.",
  },
});

/** Sort comparator: most severe first. */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY[b].rank - SEVERITY[a].rank;
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}
