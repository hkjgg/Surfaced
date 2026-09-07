import type { ComponentPropsWithRef } from "react";

import { cn } from "@/lib/cn";

/**
 * A loading placeholder. The breathing animation is switched off wholesale by
 * the `prefers-reduced-motion` rule in globals.css, leaving a static tint —
 * still a legible placeholder, just not a moving one.
 */
export function Skeleton({ className, ...props }: ComponentPropsWithRef<"div">) {
  return (
    <div
      aria-hidden="true"
      className={cn("animate-breathe rounded-sm bg-raised", className)}
      {...props}
    />
  );
}
