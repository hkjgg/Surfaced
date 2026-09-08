"use client";

import { useCallback, useMemo } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import {
  isFiltered,
  parseFilters,
  serializeFilters,
  toggleSeverity as toggle,
  type FindingFilters,
} from "@/lib/report/filters";
import type { Severity } from "@/lib/severity";

export interface FindingFilterControls extends FindingFilters {
  toggleSeverity: (severity: Severity) => void;
  setHidePassed: (hide: boolean) => void;
  clear: () => void;
  isFiltered: boolean;
}

/**
 * Filter state, held in the URL so a filtered report is shareable.
 *
 * The parsing and serialising rules live in lib/report/filters.ts; this is
 * only the wiring to the router.
 */
export function useFindingFilters(): FindingFilterControls {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const filters = useMemo(
    () => parseFilters(new URLSearchParams(searchParams.toString())),
    [searchParams],
  );

  const write = useCallback(
    (next: FindingFilters) => {
      const params = serializeFilters(
        next,
        new URLSearchParams(searchParams.toString()),
      );
      const query = params.toString();

      // replace, not push: filtering is not a navigation step, and it should
      // not take five presses of Back to leave the report.
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  return {
    ...filters,
    toggleSeverity: useCallback(
      (severity: Severity) => write(toggle(filters, severity)),
      [filters, write],
    ),
    setHidePassed: useCallback(
      (hide: boolean) => write({ ...filters, hidePassed: hide }),
      [filters, write],
    ),
    clear: useCallback(
      () => write({ severities: null, hidePassed: false }),
      [write],
    ),
    isFiltered: isFiltered(filters),
  };
}
