export function SiteFooter() {
  return (
    <footer className="mt-auto border-t border-border">
      <div className="shell py-6">
        <p className="max-w-2xl text-xs text-fg-subtle">
          Surfaced reads only publicly available data — DNS records, HTTP
          response headers, TLS certificates and Certificate Transparency logs.
          Every scan is passive and read-only. Surfaced never port scans, never
          probes for vulnerabilities, and never touches a target&rsquo;s systems.
        </p>
      </div>
    </footer>
  );
}
