import { CHECK_IDS, type CheckId, type CheckStatus } from "@/lib/scanner/types";
import { cn } from "@/lib/cn";

/** One settled check, as the terminal needs it. */
export interface TerminalLine {
  readonly check: CheckId;
  readonly status: CheckStatus;
  readonly findingCount: number;
  readonly durationMs: number;
  readonly elapsedMs?: number;
}

interface ScanTerminalProps {
  hostname: string;
  lines: readonly TerminalLine[];
  /** False once the report event has arrived. */
  running: boolean;
  /** True when the server replayed a cached scan instead of running one. */
  cached: boolean;
}

const STATUS_TEXT: Record<CheckStatus, string> = {
  ok: "ok",
  error: "unavailable",
  not_configured: "not configured",
};

const STATUS_TONE: Record<CheckStatus, string> = {
  ok: "text-pass",
  error: "text-medium",
  not_configured: "text-fg-subtle",
};

/** `1234` → `1.234s`, right-aligned by the caller's tabular figures. */
function formatSeconds(ms: number): string {
  return `${(ms / 1000).toFixed(3)}s`;
}

/**
 * The live scan log.
 *
 * Every line here is printed because a check actually settled — the timings
 * are the ones the orchestrator measured. Nothing is paced with a timer, so a
 * scan where five checks land in 40ms and the sixth takes three seconds looks
 * exactly like that, which is the useful thing to know.
 *
 * The container reserves height for all six checks up front, so lines fill
 * space that is already allocated and nothing below the terminal moves as the
 * scan progresses.
 */
export function ScanTerminal({ hostname, lines, running, cached }: ScanTerminalProps) {
  const settled = new Set(lines.map((line) => line.check));
  const waiting = CHECK_IDS.filter((id) => !settled.has(id));

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-surface shadow-1">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-2.5">
        <span className="label text-fg-subtle">
          {running ? "Scanning" : "Scan complete"}
        </span>
        <span className="label text-fg-subtle">
          {cached ? "cached · 60s" : `${lines.length}/${CHECK_IDS.length} checks`}
        </span>
      </div>

      {/* role="log" + polite: each settled check is announced as it lands,
          without stealing focus from whatever the user is doing. */}
      <div
        role="log"
        aria-live="polite"
        aria-label={`Scan progress for ${hostname}`}
        className="min-h-[13.5rem] px-4 py-3 font-mono text-xs tabular-nums"
      >
        <p className="text-fg-subtle">
          <span aria-hidden="true">$ </span>
          surfaced scan <span className="text-fg">{hostname}</span>
        </p>

        {lines.map((line) => (
          <p key={line.check} className="mt-1 flex gap-2 text-fg-muted">
            <span className="w-16 shrink-0 text-right text-fg-subtle">
              {line.elapsedMs === undefined ? "—" : formatSeconds(line.elapsedMs)}
            </span>
            <span className="w-[5.5rem] shrink-0 text-fg">{line.check}</span>
            <span className={cn("shrink-0", STATUS_TONE[line.status])}>
              {STATUS_TEXT[line.status]}
            </span>
            <span className="text-fg-subtle">
              {line.status === "ok"
                ? `${line.findingCount} finding${line.findingCount === 1 ? "" : "s"}`
                : ""}
              <span className="ml-2">{line.durationMs}ms</span>
            </span>
          </p>
        ))}

        {/* Pending checks are listed by name rather than left blank, so the
            reserved space reads as "these are still running" instead of a gap
            waiting to be filled. */}
        {waiting.map((id) => (
          <p key={id} className="mt-1 flex gap-2 text-fg-subtle/70">
            <span className="w-16 shrink-0 text-right">
              {running ? "·····" : "—"}
            </span>
            <span className="w-[5.5rem] shrink-0">{id}</span>
            <span>{running ? "running" : "no result"}</span>
          </p>
        ))}
      </div>
    </div>
  );
}
