"use client";

import { type FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * The domain field. Submitting navigates to the report for that domain.
 *
 * Validation here is deliberately minimal — empty input only. `validate.ts` on
 * the server is the real boundary, and it does considerably more than a
 * regex: public-suffix checks, IP-literal rejection, and the SSRF guards. A
 * second, weaker copy in the browser would be another thing to keep in step,
 * and would eventually disagree with the one that matters.
 */
export function DomainField() {
  const router = useRouter();
  const [value, setValue] = useState("");

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const domain = value.trim();
    if (domain.length === 0) return;

    router.push(`/scan/${encodeURIComponent(domain)}`);
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="flex w-full max-w-xl flex-col gap-3 sm:flex-row sm:items-start"
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
          fill becomes the loudest thing on the page, and the accent is meant to
          be used sparingly. */}
      <Button variant="primary" type="submit" className="self-start">
        Scan
      </Button>
    </form>
  );
}
