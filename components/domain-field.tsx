"use client";

import { type FormEvent, useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/cn";

/**
 * Targets worth a first click.
 *
 * Chosen so the four reports differ from each other — a row of buttons that
 * all return a wall of green teaches a visitor nothing about what the tool
 * measures. Each is a public site that expects to be looked at, and the scan
 * is the same single passive HTTPS request in every case.
 */
const QUICK_TRY = [
  { domain: "github.com", note: "strong posture" },
  { domain: "neverssl.com", note: "no email auth" },
  { domain: "expired.badssl.com", note: "expired certificate" },
  { domain: "example.com", note: "minimal surface" },
] as const;

interface DomainFieldProps {
  /** The quick-try row only belongs on the home page. */
  showQuickTry?: boolean;
}

/**
 * The domain field.
 *
 * Validation here is deliberately minimal — empty input only. `validate.ts` on
 * the server is the real boundary, and it does considerably more than a regex:
 * public-suffix checks, IP-literal rejection, and the SSRF guards. A second,
 * weaker copy in the browser would be another thing to keep in step, and would
 * eventually disagree with the one that matters.
 */
export function DomainField({ showQuickTry = false }: DomainFieldProps) {
  const router = useRouter();
  const [value, setValue] = useState("");
  // Real navigation state, not a timer: the button says "Scanning…" for
  // exactly as long as the transition is actually pending.
  const [pending, startTransition] = useTransition();

  function scan(domain: string) {
    const trimmed = domain.trim();
    if (trimmed.length === 0) return;

    startTransition(() => {
      router.push(`/scan/${encodeURIComponent(trimmed)}`);
    });
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    scan(value);
  }

  return (
    <div>
      <form
        onSubmit={handleSubmit}
        className={cn(
          "flex w-full max-w-xl flex-col gap-3 rounded-lg sm:flex-row sm:items-start",
          // A soft accent halo while the field has focus. The input keeps its
          // own :focus-visible outline; this sits behind it.
          "transition-shadow duration-200 focus-within:shadow-[0_0_0_6px_var(--color-accent-wash)]",
        )}
      >
        <Input
          label="Domain to scan"
          hideLabel
          name="domain"
          type="text"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          placeholder="example.com"
          aria-describedby="domain-help"
          className="sm:flex-1"
          value={value}
          onChange={(event) => setValue(event.target.value)}
        />
        {/* Natural width, not full-bleed: on a 375px screen a full-width accent
            fill becomes the loudest thing on the page, and the accent is meant
            to be used sparingly. */}
        <Button
          variant="primary"
          type="submit"
          disabled={pending}
          className="self-start"
        >
          {pending ? "Scanning…" : "Scan"}
        </Button>
      </form>

      {showQuickTry ? (
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="label mr-1 text-fg-subtle">Try</span>
          {QUICK_TRY.map((target) => (
            <button
              key={target.domain}
              type="button"
              disabled={pending}
              // Fill the field as well as navigating, so the choice is visible
              // rather than the page just changing under you.
              onClick={() => {
                setValue(target.domain);
                scan(target.domain);
              }}
              title={target.note}
              className={cn(
                "rounded-sm border border-border bg-surface px-2 py-1",
                "font-mono text-2xs text-fg-muted transition-colors duration-150",
                "hover:border-border-strong hover:bg-raised hover:text-fg",
                "disabled:pointer-events-none disabled:opacity-45",
              )}
            >
              {target.domain}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
