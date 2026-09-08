import { axisScore, SCORE_AXES } from "@/lib/scanner/score";
import type { CheckResult } from "@/lib/scanner/types";

const CENTER_X = 140;
const CENTER_Y = 96;
const MAX_R = 60;
const LABEL_R = 76;
const RINGS = [0.25, 0.5, 0.75, 1];

interface Axis {
  readonly label: string;
  readonly score: number | null;
  readonly reason: string | null;
  readonly angle: number;
  readonly point: { x: number; y: number } | null;
  readonly spokeEnd: { x: number; y: number };
  readonly labelPos: { x: number; y: number; anchor: "start" | "middle" | "end" };
}

function polar(angleDeg: number, radius: number): { x: number; y: number } {
  const radians = (angleDeg * Math.PI) / 180;
  return {
    x: CENTER_X + radius * Math.cos(radians),
    y: CENTER_Y + radius * Math.sin(radians),
  };
}

function anchorFor(angleDeg: number): "start" | "middle" | "end" {
  const x = Math.cos((angleDeg * Math.PI) / 180);
  if (x > 0.2) return "start";
  if (x < -0.2) return "end";
  return "middle";
}

function buildAxes(checks: readonly CheckResult[]): Axis[] {
  return SCORE_AXES.map((axis, index) => {
    const result = checks.find((candidate) => candidate.check === axis.check);
    const score = axisScore(result);
    // Start at the top and go clockwise.
    const angle = -90 + index * (360 / SCORE_AXES.length);

    return {
      label: axis.label,
      score,
      reason: result?.reason ?? null,
      angle,
      point: score === null ? null : polar(angle, (MAX_R * score) / 100),
      spokeEnd: polar(angle, MAX_R),
      labelPos: { ...polar(angle, LABEL_R), anchor: anchorFor(angle) },
    };
  });
}

interface ScoreRadarProps {
  checks: readonly CheckResult[];
}

/**
 * Six axes: Email, DNS, TLS, Headers, Exposure, Breaches.
 *
 * Subscores come from `axisScore` in score.ts, which reuses the same weights
 * and deductions as the headline number, so an axis can never disagree with
 * the score above it.
 *
 * An axis with no result is drawn as an explicit GAP — a dashed spoke, no
 * plotted vertex, and the edges either side of it dashed to show the shape is
 * interrupted. Plotting it at zero would be a claim that the domain failed
 * something nobody was able to look at.
 *
 * The SVG is decorative to assistive tech; the table beneath it carries the
 * same numbers, because a polygon is not readable by a screen reader.
 */
export function ScoreRadar({ checks }: ScoreRadarProps) {
  const axes = buildAxes(checks);
  const plotted = axes.filter(
    (axis): axis is Axis & { point: { x: number; y: number } } => axis.point !== null,
  );

  const fillPath =
    plotted.length >= 3
      ? `${plotted.map((axis) => `${axis.point.x},${axis.point.y}`).join(" ")}`
      : null;

  // One line per edge, so an edge that bridges a missing axis can be dashed
  // while the rest stay solid.
  const edges = plotted.map((axis, index) => {
    const next = plotted[(index + 1) % plotted.length];
    if (!next) return null;

    const from = axes.indexOf(axis);
    const to = axes.indexOf(next);
    const span = (to - from + axes.length) % axes.length;

    return {
      key: `${axis.label}-${next.label}`,
      x1: axis.point.x,
      y1: axis.point.y,
      x2: next.point.x,
      y2: next.point.y,
      // span > 1 means at least one excluded axis sits between these two.
      bridged: span > 1,
    };
  });

  const excluded = axes.filter((axis) => axis.score === null);

  return (
    <div>
      <svg
        viewBox="0 0 280 200"
        aria-hidden="true"
        className="w-full max-w-[20rem]"
      >
        {RINGS.map((ring) => (
          <polygon
            key={ring}
            points={axes
              .map((axis) => {
                const point = polar(axis.angle, MAX_R * ring);
                return `${point.x},${point.y}`;
              })
              .join(" ")}
            fill="none"
            stroke="var(--color-border)"
            strokeWidth="1"
          />
        ))}

        {axes.map((axis) => (
          <line
            key={`spoke-${axis.label}`}
            x1={CENTER_X}
            y1={CENTER_Y}
            x2={axis.spokeEnd.x}
            y2={axis.spokeEnd.y}
            stroke={
              axis.score === null
                ? "var(--color-border-strong)"
                : "var(--color-border)"
            }
            strokeWidth="1"
            strokeDasharray={axis.score === null ? "3 3" : undefined}
          />
        ))}

        {fillPath ? (
          <polygon
            points={fillPath}
            fill="var(--color-accent-wash)"
            stroke="none"
          />
        ) : null}

        {edges.map((edge) =>
          edge ? (
            <line
              key={edge.key}
              x1={edge.x1}
              y1={edge.y1}
              x2={edge.x2}
              y2={edge.y2}
              stroke="var(--color-accent)"
              strokeWidth="1.5"
              strokeDasharray={edge.bridged ? "4 4" : undefined}
            />
          ) : null,
        )}

        {plotted.map((axis) => (
          <circle
            key={`point-${axis.label}`}
            cx={axis.point.x}
            cy={axis.point.y}
            r="3"
            fill="var(--color-accent)"
          />
        ))}

        {axes.map((axis) => (
          <text
            key={`label-${axis.label}`}
            x={axis.labelPos.x}
            y={axis.labelPos.y}
            textAnchor={axis.labelPos.anchor}
            dominantBaseline="middle"
            fontSize="9"
            fontFamily="var(--font-mono)"
            letterSpacing="0.08em"
            fill={
              axis.score === null
                ? "var(--color-fg-subtle)"
                : "var(--color-fg-muted)"
            }
          >
            {axis.label.toUpperCase()}
            <tspan
              x={axis.labelPos.x}
              dy="10"
              fontSize="8"
              letterSpacing="0"
              fill={
                axis.score === null
                  ? "var(--color-fg-subtle)"
                  : "var(--color-fg-muted)"
              }
            >
              {axis.score === null ? "not checked" : axis.score}
            </tspan>
          </text>
        ))}
      </svg>

      {/* The sr-only utility has to go on a wrapping div, not on the table:
          `overflow: hidden` does not contain a table box, so the table keeps
          its full intrinsic width and drags the document's scrollWidth out
          with it — an invisible element causing real horizontal overflow. */}
      <div className="sr-only">
        <table>
          <caption>Score by area</caption>
          <thead>
            <tr>
              <th scope="col">Area</th>
              <th scope="col">Score</th>
            </tr>
          </thead>
          <tbody>
            {axes.map((axis) => (
              <tr key={axis.label}>
                <th scope="row">{axis.label}</th>
                <td>
                  {axis.score === null
                    ? `Not checked. ${axis.reason ?? "The check returned no result."}`
                    : `${axis.score} out of 100`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {excluded.length > 0 ? (
        <p className="mt-2 text-xs text-fg-subtle">
          <span className="text-fg-muted">Gaps:</span>{" "}
          {excluded.map((axis) => axis.label).join(", ")} could not be checked, so
          {excluded.length === 1 ? " that axis is" : " those axes are"} left
          empty rather than scored zero.
        </p>
      ) : null}
    </div>
  );
}
