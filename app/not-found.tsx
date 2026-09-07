import Link from "next/link";

export default function NotFound() {
  return (
    <div className="shell flex flex-col py-16 sm:py-24">
      <span className="label text-fg-subtle">Error 404</span>
      <h1 className="mt-2 text-2xl font-medium tracking-tight text-fg">
        No such page
      </h1>
      <p className="mt-3 max-w-md text-base text-fg-muted">
        That route doesn&rsquo;t exist.
      </p>
      <Link
        href="/"
        className="mt-6 w-fit rounded-xs text-sm text-accent underline underline-offset-4 hover:text-fg"
      >
        Back to the scanner
      </Link>
    </div>
  );
}
