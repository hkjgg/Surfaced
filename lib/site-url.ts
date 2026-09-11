/**
 * The deployment's own origin, validated.
 *
 * Open Graph needs absolute URLs, which means the app has to know where it is
 * deployed — something it can only learn from the environment. That is exactly
 * the situation CLAUDE.md §4 is about, so this module follows the same shape as
 * lib/supabase/env.ts:
 *
 *   1. never throws — absent or malformed config returns null;
 *   2. parses with `new URL()` and returns the PARSED origin, never the raw
 *      string;
 *   3. is not read at module scope, so importing it during a build is inert.
 *
 * When it returns null, `metadataBase` is simply left unset. The build still
 * succeeds with an empty environment; social previews degrade rather than the
 * deploy breaking.
 *
 * This supersedes the earlier "no metadataBase at all" decision, which was
 * correct while nothing needed an absolute URL and is not correct now.
 */

/**
 * A bare hostname, as Vercel supplies. Deliberately strict.
 *
 * This is checked BEFORE a scheme is attached, because prefixing "https://"
 * onto an unvalidated string is the string concatenation CLAUDE.md forbids:
 * `evil.com/@real.app` or a value carrying credentials would otherwise parse
 * into a URL pointing somewhere other than it appears to.
 */
const BARE_HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

function parseHttpsOrigin(raw: string | undefined): string | null {
  if (!raw) return null;

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return null;
  }

  if (parsed.protocol !== "https:") return null;
  // Credentials in a site URL are always a mistake and sometimes an attack.
  if (parsed.username || parsed.password) return null;

  return parsed.origin;
}

function parseBareHostname(raw: string | undefined): string | null {
  const value = raw?.trim();
  if (!value || !BARE_HOSTNAME.test(value)) return null;

  // Only now, having established it is nothing but a hostname, is it safe to
  // build a URL from it — and the parsed result is what gets returned.
  return parseHttpsOrigin(`https://${value}`);
}

/**
 * The canonical origin, or null when it cannot be determined.
 *
 * `NEXT_PUBLIC_SITE_URL` wins: it is the value a human set deliberately.
 * Vercel's `VERCEL_PROJECT_PRODUCTION_URL` is the fallback so that a normal
 * deploy gets working social previews without any configuration.
 */
export function getSiteUrl(): URL | null {
  const origin =
    parseHttpsOrigin(process.env.NEXT_PUBLIC_SITE_URL) ??
    parseBareHostname(process.env.VERCEL_PROJECT_PRODUCTION_URL);

  if (!origin) return null;

  try {
    return new URL(origin);
  } catch {
    return null;
  }
}
