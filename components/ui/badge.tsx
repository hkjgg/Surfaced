import type { ComponentPropsWithRef } from "react";

import { cn } from "@/lib/cn";
import { SEVERITY, type Severity } from "@/lib/severity";

type BadgeVariant = "neutral" | "accent" | Severity;

const VARIANTS: Record<BadgeVariant, string> = {
  neutral: "bg-raised text-fg-muted border-border",
  accent: "bg-accent-wash text-accent border-accent-edge",
  critical: "bg-critical-wash text-critical border-critical-edge",
  high: "bg-high-wash text-high border-high-edge",
  medium: "bg-medium-wash text-medium border-medium-edge",
  low: "bg-low-wash text-low border-low-edge",
  pass: "bg-pass-wash text-pass border-pass-edge",
};

export interface BadgeProps extends ComponentPropsWithRef<"span"> {
  variant?: BadgeVariant;
}

/**
 * For the five severity variants the badge renders a rank meter alongside the
 * label, so severity is legible without colour — in greyscale, or to a viewer
 * with a colour-vision deficiency. The meter is aria-hidden because the label
 * beside it already carries the same meaning in text.
 */
export function Badge({
  className,
  variant = "neutral",
  children,
  ...props
}: BadgeProps) {
  const severity = variant in SEVERITY ? SEVERITY[variant as Severity] : null;

  return (
    <span
      className={cn(
        "label inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5",
        VARIANTS[variant],
        className,
      )}
      {...props}
    >
      {severity ? (
        <>
          <span aria-hidden="true" className="tracking-normal">
            {severity.meter}
          </span>
          <span>{children ?? severity.label}</span>
        </>
      ) : (
        children
      )}
    </span>
  );
}
