"use client";

import { type ComponentPropsWithRef, useId } from "react";

import { cn } from "@/lib/cn";

export interface InputProps extends ComponentPropsWithRef<"input"> {
  /** Always required. Pass `hideLabel` to keep it visually hidden but announced. */
  label: string;
  hideLabel?: boolean;
  description?: string;
  error?: string;
  /**
   * Monospace by default: this input mostly holds domains, and a domain is a
   * machine-readable string that should be scannable character by character.
   */
  mono?: boolean;
}

export function Input({
  className,
  label,
  hideLabel = false,
  description,
  error,
  mono = true,
  id,
  ...props
}: InputProps) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  const describedBy =
    [description ? `${inputId}-description` : null, error ? `${inputId}-error` : null]
      .filter(Boolean)
      .join(" ") || undefined;

  return (
    <div className="flex w-full flex-col gap-1.5">
      <label
        htmlFor={inputId}
        className={cn("label text-fg-muted", hideLabel && "sr-only")}
      >
        {label}
      </label>

      <input
        id={inputId}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={cn(
          "h-10 w-full rounded-md border bg-raised px-3 text-base text-fg",
          "placeholder:text-fg-subtle transition-colors duration-150",
          "hover:border-border-strong disabled:cursor-not-allowed disabled:opacity-45",
          mono && "font-mono tabular-nums",
          error ? "border-critical" : "border-border",
          className,
        )}
        {...props}
      />

      {description ? (
        <p id={`${inputId}-description`} className="text-xs text-fg-subtle">
          {description}
        </p>
      ) : null}

      {error ? (
        <p id={`${inputId}-error`} className="text-xs text-critical">
          {error}
        </p>
      ) : null}
    </div>
  );
}
