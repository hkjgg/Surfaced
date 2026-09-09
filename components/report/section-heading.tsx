import { cn } from "@/lib/cn";

interface SectionHeadingProps {
  id: string;
  children: React.ReactNode;
  /** Right-aligned detail: a count, a duration. */
  meta?: React.ReactNode;
  className?: string;
}

/**
 * The recurring section header.
 *
 * These were `text-fg-subtle` with no rule, which left them too quiet to
 * anchor anything — scrolling past, there was nothing to tell you which part
 * of the report you were in. A rule and one step more contrast is enough;
 * anything louder starts competing with the score.
 */
export function SectionHeading({
  id,
  children,
  meta,
  className,
}: SectionHeadingProps) {
  return (
    <div
      className={cn(
        "mb-3 flex items-baseline justify-between gap-3 border-b border-border pb-1.5",
        className,
      )}
    >
      <h2 id={id} className="label text-fg-muted">
        {children}
      </h2>
      {meta ? <span className="label text-fg-subtle">{meta}</span> : null}
    </div>
  );
}
