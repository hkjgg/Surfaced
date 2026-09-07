import type { ComponentPropsWithRef } from "react";

import { cn } from "@/lib/cn";

/**
 * Elevation on a dark UI comes from surface lightness and a hairline border
 * first; shadow is a whisper on top of that, not the mechanism.
 */
export function Card({ className, ...props }: ComponentPropsWithRef<"div">) {
  return (
    <div
      className={cn(
        "rounded-lg border border-border bg-surface shadow-1",
        className,
      )}
      {...props}
    />
  );
}

export interface CardHeaderProps extends ComponentPropsWithRef<"div"> {
  /** Uppercase mono micro-label, e.g. "DNS · SPF". */
  eyebrow?: string;
}

export function CardHeader({
  className,
  eyebrow,
  children,
  ...props
}: CardHeaderProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-1 border-b border-border px-4 py-3 sm:px-5",
        className,
      )}
      {...props}
    >
      {eyebrow ? <span className="label text-fg-subtle">{eyebrow}</span> : null}
      {children}
    </div>
  );
}

export function CardTitle({ className, ...props }: ComponentPropsWithRef<"h2">) {
  return (
    <h2
      className={cn("text-lg font-medium tracking-tight text-fg", className)}
      {...props}
    />
  );
}

export function CardBody({ className, ...props }: ComponentPropsWithRef<"div">) {
  return <div className={cn("px-4 py-4 sm:px-5", className)} {...props} />;
}
