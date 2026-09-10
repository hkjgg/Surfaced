"use client";

import { useEffect, useState } from "react";

import { TONE_TEXT } from "@/components/report/tone";
import { useReducedMotion } from "@/components/report/use-reduced-motion";
import { cn } from "@/lib/cn";
import { scoreBand } from "@/lib/scanner/score";
import type { ScanScore } from "@/lib/scanner/types";
import { SEVERITY, type Severity } from "@/lib/severity";
import { CHECK_IDS } from "@/lib/scanner/types";

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const COUNT_MS = 700;

/**
 * Band wording for a SCORE, which is not the same sentence as band wording for
 * a finding.
 *
 * The ramp's own labels read wrong here: "89 · LOW" invites exactly the
 * misreading that the score is low, when the band means the opposite — few and
 * minor problems. The colour and the rank meter still come straight from the
 * ramp, so the visual scale is unchanged; only the words are fitted to what
 * they are describing.
 */
const BAND_LABEL: Record<Severity, string> = {
  pass: "Strong",
  low: "Minor issues",
  medium: "Needs work",
  high: "Weak",
  critical: "Critical",
};

/** Same reasoning as BAND_LABEL: the ramp's `meaning` describes one finding. */
const BAND_MEANING: Record<Severity, string> = {
  pass: "Nothing significant found in the checks that ran.",
  low: "Minor hardening opportunities only.",
  medium: "Real gaps worth scheduling.",
  high: "Clear weaknesses with a path to harm.",
  critical: "Exploitable or actively harmful configuration.",
};

function useCountUp(target: number | null, enabled: boolean): number {
  const [value, setValue] = useState(() => (enabled ? 0 : (target ?? 0)));

  useEffect(() => {
    if (target === null) return;

    if (!enabled) {
      setValue(target);
      return;
    }

    let frame = 0;
    const started = performance.now();

    const tick = (now: number) => {
      const progress = Math.min(1, (now - started) / COUNT_MS);
      // easeOutCubic: fast to begin with, settling rather than stopping dead.
      const eased = 1 - Math.pow(1 - progress, 3);

      setValue(Math.round(target * eased));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, enabled]);

  return value;
}

interface ScoreGaugeProps {
  score: ScanScore;
}

/**
 * The score readout.
 *
 * The arc is coloured from the severity ramp; the numeral keeps the accent.
 * This is the one place the two scales deliberately meet — the arc states a
 * verdict so it should read as one, while the number stays the page's single
 * accent anchor. Colour is never the only channel either way: the band label
 * and its rank meter sit beside the number.
 *
 * The numeral uses --text-score (48px → 72px) because it is the conclusion of
 * the whole report and should be the largest thing on the page.
 */
export function ScoreGauge({ score }: ScoreGaugeProps) {
  const reducedMotion = useReducedMotion();
  const animate = !reducedMotion;
  const displayed = useCountUp(score.value, animate);

  const band = score.value === null ? null : scoreBand(score.value);
  const offset =
    score.value === null
      ? CIRCUMFERENCE
      : CIRCUMFERENCE * (1 - score.value / 100);

  const included = score.checksIncluded.length;

  // The coverage count belongs INSIDE the accessible name. A screen-reader
  // user must not be handed "92 out of 100" with the caveat parked in a
  // separate paragraph they may never reach.
  const description =
    score.value === null
      ? `Not scored. None of the ${CHECK_IDS.length} checks returned a usable result.`
      : `${score.value} out of 100, ${
          band ? BAND_LABEL[band].toLowerCase() : ""
        }. Based on ${included} of ${CHECK_IDS.length} checks${
          score.partial ? ", so this is a partial score" : ""
        }.`;

  return (
    <div className="flex items-center gap-5">
      <div className="relative shrink-0">
        <svg
          viewBox="0 0 120 120"
          role="img"
          aria-label={description}
          className="h-[8.5rem] w-[8.5rem] -rotate-90 sm:h-[10rem] sm:w-[10rem]"
        >
          <circle
            cx="60"
            cy="60"
            r={RADIUS}
            fill="none"
            stroke="var(--color-border)"
            strokeWidth="8"
          />
          {score.value === null ? null : (
            <circle
              cx="60"
              cy="60"
              r={RADIUS}
              fill="none"
              stroke="currentColor"
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={CIRCUMFERENCE}
              strokeDashoffset={offset}
              className={cn(band ? TONE_TEXT[band] : "", "animate-gauge")}
              style={
                {
                  "--gauge-empty": CIRCUMFERENCE,
                  "--gauge-offset": offset,
                } as React.CSSProperties
              }
            />
          )}
        </svg>

        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          {score.value === null ? (
            <span className="label text-fg-subtle">Not scored</span>
          ) : (
            <span
              aria-hidden="true"
              className="font-mono text-score font-medium tabular-nums tracking-display text-accent"
            >
              {displayed}
            </span>
          )}
        </div>
      </div>

      <div className="min-w-0">
        <p className="label text-fg-subtle">Score</p>

        {band ? (
          <p className={cn("mt-1 flex items-center gap-2", TONE_TEXT[band])}>
            <span aria-hidden="true" className="font-mono text-sm">
              {SEVERITY[band].meter}
            </span>
            <span className="label">{BAND_LABEL[band]}</span>
          </p>
        ) : null}

        <p className="mt-1.5 text-xs text-fg-muted">
          {score.value === null
            ? "No check returned a usable result."
            : `${included} of ${CHECK_IDS.length} checks scored`}
        </p>

        {band ? (
          <p className="mt-1 max-w-[22ch] text-xs text-fg-subtle">
            {BAND_MEANING[band]}
          </p>
        ) : null}
      </div>
    </div>
  );
}
