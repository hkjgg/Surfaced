import { DomainField } from "@/components/domain-field";
import { Wordmark } from "@/components/layout/wordmark";

export default function HomePage() {
  return (
    <div className="shell flex flex-col justify-center py-16 sm:py-24">
      <Wordmark size="lg" />

      <p className="mt-4 max-w-xl text-base text-fg-muted">
        See what your domain reveals to anyone who looks — DNS, headers,
        certificates — scored and ranked, without touching your systems.
      </p>

      <div className="mt-8">
        <DomainField />
        <p id="domain-help" className="mt-2.5 text-xs text-fg-subtle">
          Scanning isn&rsquo;t wired up yet.
        </p>
      </div>
    </div>
  );
}
