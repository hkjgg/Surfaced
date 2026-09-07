import { cn } from "@/lib/cn";

/**
 * The wordmark is pure type: lowercase mono plus a terminal cursor block.
 *
 * No icon, and specifically no shield, padlock, matrix green, or hooded
 * figure. Surfaced is an engineering tool; it should look like one.
 */
export function Wordmark({
  className,
  size = "sm",
}: {
  className?: string;
  size?: "sm" | "lg";
}) {
  return (
    <span
      className={cn(
        "inline-flex items-baseline font-mono font-medium tracking-tight text-fg",
        size === "sm" ? "text-base" : "text-2xl sm:text-3xl",
        className,
      )}
    >
      surfaced
      <span
        aria-hidden="true"
        className={cn(
          "ml-0.5 text-accent",
          size === "sm" ? "text-base" : "text-2xl sm:text-3xl",
        )}
      >
        ▮
      </span>
    </span>
  );
}
