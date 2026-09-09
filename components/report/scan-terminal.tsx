"use client";

import { useId, useState } from "react";

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
  /** Total wall time from the report, once there is one. */
  durationMs?: number;
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

/** `1234` → `1.234s`, aligned by the caller's tabular figures. */
function formatSeconds(ms: number): string {
  return `${(ms / 1000).toFixed(3)}s`;
}

/**
 * The live scan log.
 *
 * Every line is printed because a check actually settled — the timings are the
 * ones the orchestrator measured. Nothing is paced with a timer, so a scan
 * where five checks land in 40ms and the sixth takes three seconds looks
 * exactly like that.
 *
 * While the scan runs this is the tallest thing on the page, and it reserves
 * height for all six checks so nothing below it moves as lines arrive. Once
 * the scan settles it collapses to a single summary line: the space belongs to
 * the results, and the log is one click away for anyone who wants it. The
 * collapse and the report's first render happen in the same commit, so there
 * is one reflow rather than two.
 */
export function ScanTerminal({
  hostname,
  lines,
  running,
  cached,
  durationMs,
}: ScanTerminalProps) {
  const [reopened, setReopened] = useState(false);
  const logId = useId();

  const expanded = running || reopened;

  const settled = new Set(lines.map((line) => line.check));
  const waiting = CHECK_IDS.filter((id) => !settled.has(id));
  const failed = lines.filter((line) => line.status !== "ok").length;

  const elapsed =
    durationMs ?? lines.reduce((max, line) => Math.max(max, line.elapsedMs ?? 0), 0);

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-surface shadow-1">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-2.5">
        <span className="label text-fg-subtle">
          {running ? "Scanning" : "Scan complete"}
        </span>

        {running ? (
          <span className="label text-fg-subtle">
            {cached ? "cached · 60s" : `${lines.length}/${CHECK_IDS.length} checks`}
          </span>
        ) : (
          <button
            type="button"
            onClick={() => setReopened((value) => !value)}
            aria-expanded={expanded}
            aria-controls={logId}
            className="label rounded-sm px-2 py-0.5 text-fg-subtle transition-colors duration-150 hover:bg-raised hover:text-fg-muted"
          >
            {expanded ? "Hide log" : "Show log"}
          </button>
        )}
      </div>

      {/* The settled summary. One line, and it stays visible when the log is
          reopened so the header does not lose its subject. */}
      {!running ? (
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 font-mono text-xs tabular-nums">
          <span className={failed === 0 ? "text-pass" : "text-medium"}>
            <span aria-hidden="true">{failed === 0 ? "✓" : "!"}</span>{" "}
            {lines.length} check{lines.length === 1 ? "" : "s"}
          </span>
          {failed > 0 ? (
            <span className="text-fg-subtle">{failed} unavailable</span>
          ) : null}
          <span className="text-fg-subtle">·</span>
          <span className="text-fg-muted">
            {cached ? "served from cache" : formatSeconds(elapsed)}
          </span>
          <span className="text-fg-subtle" data-mono>
            {hostname}
          </span>
        </p>
      ) : null}

      {/* role="log" + polite: each settled check is announced as it lands,
          without stealing focus. Only rendered while it is the live surface or
          the reader has asked for it back. */}
      {expanded ? (
        <div
          id={logId}
          role={running ? "log" : undefined}
          aria-live={running ? "polite" : undefined}
          aria-label={`Scan progress for ${hostname}`}
          className={cn(
            "px-4 py-3 font-mono text-xs tabular-nums",
            running && "min-h-[13.5rem]",
            !running && "border-t border-border",
          )}
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
              reserved space reads as "these are still running" instead of a
              gap waiting to be filled. */}
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
      ) : null}
    </div>
  );
}
