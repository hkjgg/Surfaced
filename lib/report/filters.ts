/**
 * Finding filter state, as pure functions over a query string.
 *
 * Kept out of the React hook so it can be exercised without a browser or a
 * router — the parsing rules below are the kind of thing that quietly rots,
 * and they are the difference between a shared URL working and a report
 * appearing empty.
 */

import { SEVERITIES, isSeverity, type Severity } from "@/lib/severity";
import type { Finding } from "@/lib/scanner/types";

export const SEV_PARAM = "sev";
export const PASSED_PARAM = "passed";

export interface FindingFilters {
  /** null means every severity — the default, and what an empty selection means. */
  readonly severities: readonly Severity[] | null;
  readonly hidePassed: boolean;
}

export const NO_FILTERS: FindingFilters = { severities: null, hidePassed: false };

/**
 * Read filters out of a query string.
 *
 * Deliberately forgiving: an unknown severity in `?sev=` is dropped rather
 * than throwing, because these URLs get shared, truncated and hand-edited. A
 * filter parameter is not a security boundary, and a report that broke on a
 * mangled query string would be worse than one that shows everything.
 */
export function parseFilters(params: URLSearchParams): FindingFilters {
  const raw = params.get(SEV_PARAM);

  const severities = raw
    ? raw
        .split(",")
        .map((value) => value.trim().toLowerCase())
        .filter(isSeverity)
    : [];

  return {
    // An empty selection means "show everything", never "show nothing" — an
    // empty results pane after one stray click is a bad default.
    severities: severities.length > 0 ? dedupe(severities) : null,
    hidePassed: params.get(PASSED_PARAM) === "0",
  };
}

function dedupe(severities: readonly Severity[]): Severity[] {
  // Canonical order, so two clients that picked the same set produce the same
  // shareable URL.
  return SEVERITIES.filter((severity) => severities.includes(severity));
}

/** Write filters back into a query string, preserving unrelated parameters. */
export function serializeFilters(
  filters: FindingFilters,
  base: URLSearchParams = new URLSearchParams(),
): URLSearchParams {
  const params = new URLSearchParams(base.toString());

  if (filters.severities && filters.severities.length > 0) {
    params.set(SEV_PARAM, dedupe(filters.severities).join(","));
  } else {
    params.delete(SEV_PARAM);
  }

  if (filters.hidePassed) params.set(PASSED_PARAM, "0");
  else params.delete(PASSED_PARAM);

  return params;
}

export function isFiltered(filters: FindingFilters): boolean {
  return filters.severities !== null || filters.hidePassed;
}

export function toggleSeverity(
  filters: FindingFilters,
  severity: Severity,
): FindingFilters {
  const current = filters.severities ?? [];
  const next = current.includes(severity)
    ? current.filter((value) => value !== severity)
    : [...current, severity];

  return { ...filters, severities: next.length > 0 ? dedupe(next) : null };
}

/** Apply the current filters to the report's findings. */
export function applyFilters(
  findings: readonly Finding[],
  filters: FindingFilters,
): Finding[] {
  return findings.filter((finding) => {
    if (filters.hidePassed && finding.severity === "pass") return false;
    if (filters.severities && !filters.severities.includes(finding.severity)) {
      return false;
    }
    return true;
  });
}
