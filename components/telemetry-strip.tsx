import {
  CHECK_COUNT,
  IMPLEMENTED_RFCS,
  SCAN_DURATION_LABEL,
} from "@/lib/scan-facts";

/**
 * The engine's vital statistics, in the tool's own register.
 *
 * Every figure is real: the check count is derived from CHECK_IDS, the
 * duration is a recorded measurement, and each RFC is cited by a finding the
 * engine actually emits. See lib/scan-facts.ts — the provenance lives with the
 * values, not here.
 */
export function TelemetryStrip() {
  const items = [
    `${CHECK_COUNT} passive checks`,
    SCAN_DURATION_LABEL,
    "read-only",
    `RFC ${IMPLEMENTED_RFCS.join(" / ")}`,
  ];

  return (
    <ul className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
      {items.map((item, index) => (
        <li key={item} className="flex items-center gap-3">
          {index > 0 ? (
            <span aria-hidden="true" className="text-fg-subtle/50">
              ·
            </span>
          ) : null}
          <span className="label text-fg-subtle">{item}</span>
        </li>
      ))}
    </ul>
  );
}
