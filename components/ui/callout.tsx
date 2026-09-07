import type { ComponentPropsWithRef } from "react";

import { cn } from "@/lib/cn";

type CalloutTone = "note" | "warn" | "critical";

const TONES: Record<CalloutTone, string> = {
  note: "border-border bg-surface text-fg-muted",
  warn: "border-medium-edge bg-medium-wash text-fg-muted",
  critical: "border-critical-edge bg-critical-wash text-fg-muted",
};

const TITLE_TONES: Record<CalloutTone, string> = {
  note: "text-fg-subtle",
  warn: "text-medium",
  critical: "text-critical",
};

export interface CalloutProps extends ComponentPropsWithRef<"div"> {
  tone?: CalloutTone;
  /** Rendered as an uppercase mono label above the body. */
  title?: string;
}

export function Callout({
  className,
  tone = "note",
  title,
  children,
  ...props
}: CalloutProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-1.5 rounded-md border px-3.5 py-3 text-sm",
        TONES[tone],
        className,
      )}
      {...props}
    >
      {title ? (
        <span className={cn("label", TITLE_TONES[tone])}>{title}</span>
      ) : null}
      {children}
    </div>
  );
}
