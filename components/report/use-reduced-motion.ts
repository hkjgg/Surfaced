"use client";

import { useEffect, useState } from "react";

const QUERY = "(prefers-reduced-motion: reduce)";

/**
 * Whether the viewer has asked for reduced motion.
 *
 * globals.css already neutralises CSS animation and transitions under this
 * media query, so most of the report needs nothing. This hook exists for the
 * one thing that rule cannot reach: a `requestAnimationFrame` loop. A JS
 * counter will happily keep animating a number for a user who asked for
 * stillness, because it never touches the CSS animation pipeline.
 *
 * Initial state is read synchronously so the first painted frame is already
 * correct — no flash of a counting number before the preference is applied.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === "undefined" || !window.matchMedia) return true;
    return window.matchMedia(QUERY).matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;

    const media = window.matchMedia(QUERY);
    const update = () => setReduced(media.matches);

    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return reduced;
}
