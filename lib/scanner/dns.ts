/**
 * Nameserver, mail-exchanger and DNSSEC posture.
 *
 * All ordinary public record lookups. DS comes over DoH because node:dns
 * cannot query it — see internal/doh.ts.
 */

import { getDomain } from "tldts";

import type { CheckResult, Finding } from "./types";
import { lookupDnssec, type DnssecResult } from "./internal/doh";
import { resolveMx, resolveNs, resolveSoa, type MxRecord, type SoaRecord } from "./internal/resolver";

const CHECK = "dns" as const;

export interface DnsData {
  /** The registrable domain, e.g. golang.org for proxy.golang.org. */
  readonly registrableDomain: string | null;
  /** True when the scanned name is a subdomain rather than a zone apex. */
  readonly isSubdomain: boolean;
  readonly nameservers: readonly string[];
  readonly mx: readonly MxRecord[];
  /**
   * RFC 7505 "null MX": a single MX with an empty exchange at preference 0.
   * It is an explicit, correct declaration that the domain receives no mail —
   * the opposite of a misconfiguration, and it must not be reported as one.
   */
  readonly nullMx: boolean;
  readonly soa: SoaRecord | null;
  readonly dnssec: DnssecResult | null;
  /** Why DNSSEC is null, when it is. */
  readonly dnssecError: string | null;
}

/** Distinct registrable parents, e.g. ns1.foo.net + ns2.foo.net -> 1. */
function distinctNameserverParents(nameservers: readonly string[]): number {
  const parents = new Set(
    nameservers.map((ns) => ns.toLowerCase().split(".").slice(-2).join(".")),
  );
  return parents.size;
}

export async function checkDns(
  hostname: string,
  signal: AbortSignal,
): Promise<CheckResult<DnsData>> {
  const started = Date.now();
  signal.throwIfAborted();

  // Delegation lives at the zone apex. A subdomain legitimately has no NS
  // records of its own, so "no NS" is only a fault for a registrable domain —
  // reporting it for a subdomain would invent a registrar problem that does
  // not exist.
  const registrableDomain = getDomain(hostname);
  const isSubdomain = registrableDomain !== null && registrableDomain !== hostname;

  const [nameservers, mx, soa, dnssecSettled] = await Promise.all([
    resolveNs(hostname),
    resolveMx(hostname),
    resolveSoa(hostname).catch(() => null),
    lookupDnssec(hostname, signal).then(
      (value) => ({ ok: true as const, value }),
      (error: unknown) => ({
        ok: false as const,
        error: error instanceof Error ? error.message : "DNSSEC lookup failed",
      }),
    ),
  ]);

  const findings: Finding[] = [];

  const nullMx =
    mx.length === 1 && (mx[0]?.exchange ?? "") === "" && mx[0]?.priority === 0;

  // ---- Nameservers --------------------------------------------------------
  if (nameservers.length === 0 && isSubdomain) {
    findings.push({
      id: "dns.ns.delegated-to-parent",
      check: CHECK,
      severity: "pass",
      title: "Nameservers are inherited from the parent zone",
      observed: `${hostname} publishes no NS records of its own, which is normal for a subdomain: it is served by the ${registrableDomain} zone.`,
      impact:
        "Delegation is handled at the registrable domain. Scan " +
        `${registrableDomain} to assess nameserver redundancy.`,
    });
  } else if (nameservers.length === 0) {
    findings.push({
      id: "dns.ns.none",
      check: CHECK,
      severity: "high",
      title: "No NS records returned",
      observed: `${hostname} returned no NS records.`,
      impact:
        "Without nameserver records the domain cannot be resolved reliably. This usually indicates a delegation problem at the registrar.",
      remediation: {
        summary: "Check the delegation at your registrar and confirm the zone is published.",
      },
    });
  } else if (nameservers.length === 1) {
    findings.push({
      id: "dns.ns.single",
      check: CHECK,
      severity: "medium",
      title: "Only one nameserver",
      observed: `${hostname} is served by a single nameserver: ${nameservers[0]}.`,
      impact:
        "A single nameserver is a single point of failure. If it becomes unreachable the domain stops resolving entirely — mail, web and everything else.",
      remediation: {
        summary: "Add at least one more nameserver, ideally on separate infrastructure.",
        reference: "RFC 1034 §4.1",
      },
    });
  } else if (distinctNameserverParents(nameservers) === 1) {
    findings.push({
      id: "dns.ns.single-provider",
      check: CHECK,
      severity: "low",
      title: "All nameservers share one parent domain",
      observed: `All ${nameservers.length} nameservers sit under one parent: ${nameservers.join(", ")}.`,
      impact:
        "Redundancy within a single provider survives one server failing, but not that provider having an outage.",
      remediation: {
        summary: "Consider secondary DNS with a second, independent provider.",
      },
    });
  } else {
    findings.push({
      id: "dns.ns.redundant",
      check: CHECK,
      severity: "pass",
      title: "Multiple nameservers across providers",
      observed: `${nameservers.length} nameservers: ${nameservers.join(", ")}.`,
      impact: "The domain keeps resolving if one nameserver or provider fails.",
    });
  }

  // ---- Mail exchangers ----------------------------------------------------
  if (nullMx) {
    findings.push({
      id: "dns.mx.null",
      check: CHECK,
      severity: "pass",
      title: "Domain explicitly accepts no mail (null MX)",
      observed: `${hostname} publishes a null MX record (empty exchange, preference 0).`,
      impact:
        "This is the correct way to declare that a domain receives no mail. Senders reject undeliverable mail immediately rather than queueing it.",
    });
  } else if (mx.length === 0) {
    findings.push({
      id: "dns.mx.none",
      check: CHECK,
      severity: "low",
      title: "No MX records",
      observed: `${hostname} publishes no MX records and no null MX.`,
      impact:
        "The domain receives no mail, but it has not said so explicitly. A null MX record tells senders to fail immediately instead of retrying for days, and makes the intent unambiguous.",
      remediation: {
        summary:
          "If this domain is not meant to receive mail, publish a null MX to say so explicitly.",
        dnsRecord: { name: hostname, type: "MX", value: "0 ." },
        reference: "RFC 7505",
      },
    });
  } else {
    findings.push({
      id: "dns.mx.present",
      check: CHECK,
      severity: "pass",
      title: `${mx.length} mail exchanger${mx.length === 1 ? "" : "s"} published`,
      observed: mx
        .map((record) => `${record.priority} ${record.exchange}`)
        .join(", "),
      impact: "The domain has somewhere to deliver inbound mail.",
    });
  }

  // ---- DNSSEC -------------------------------------------------------------
  const dnssec = dnssecSettled.ok ? dnssecSettled.value : null;
  const dnssecError = dnssecSettled.ok ? null : dnssecSettled.error;

  if (!dnssec) {
    // Deliberately NOT reported as "unsigned". A failed lookup and an unsigned
    // zone are different facts, and conflating them would be a false negative
    // on a security control.
    findings.push({
      id: "dnssec.unknown",
      check: CHECK,
      severity: "low",
      title: "DNSSEC status could not be determined",
      observed: `The DS lookup did not complete: ${dnssecError ?? "unknown error"}.`,
      impact:
        "This is not a finding about the domain — it means the check could not reach a DNS-over-HTTPS resolver. The domain may or may not be signed.",
    });
  } else if (dnssec.signed) {
    findings.push({
      id: "dnssec.signed",
      check: CHECK,
      severity: "pass",
      title: "DNSSEC is enabled",
      observed: `The parent zone publishes ${dnssec.dsRecords.length} DS record${
        dnssec.dsRecords.length === 1 ? "" : "s"
      } (via ${dnssec.resolver}).`,
      impact:
        "Resolvers can verify that answers for this domain have not been tampered with in transit.",
    });
  } else {
    findings.push({
      id: "dnssec.absent",
      check: CHECK,
      severity: "low",
      title: "DNSSEC is not enabled",
      observed: `No DS record is published for ${hostname} at its parent zone (checked via ${dnssec.resolver}).`,
      impact:
        "Without DNSSEC, a resolver cannot detect forged DNS answers, which makes cache-poisoning and on-path redirection harder to rule out.",
      remediation: {
        summary:
          "Enable DNSSEC signing with your DNS provider, then publish the resulting DS record at your registrar.",
        reference: "RFC 4033",
      },
    });
  }

  return {
    check: CHECK,
    status: "ok",
    findings,
    data: {
      registrableDomain,
      isSubdomain,
      nameservers,
      mx,
      nullMx,
      soa,
      dnssec,
      dnssecError,
    },
    durationMs: Date.now() - started,
  };
}
