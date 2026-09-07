"use client";

import type { FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * The home page's domain field. Inert by design — scanning does not exist yet.
 *
 * It is a real <form> with a real <label> rather than a decorative div, so the
 * keyboard and screen-reader behaviour is correct from the start and the
 * scanner step only has to replace the submit handler.
 */
export function DomainField() {
  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    // No scanner yet. Swallow the submit rather than reloading the page.
    event.preventDefault();
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
