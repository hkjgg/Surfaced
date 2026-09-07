/**
 * Supabase configuration, validated.
 *
 * Surfaced must build and run with NO environment variables set. That is a
 * hard requirement, so this module:
 *
 *   1. never throws — absent or malformed config returns null;
 *   2. never constructs a URL by string concatenation. The value is parsed
 *      with `new URL()` and rejected unless it parses AND is https. An
 *      unvalidated env var interpolated into a request target is how you end
 *      up sending credentials to somebody else's host.
 *   3. is not evaluated at module scope, so importing it during a build is
 *      inert.
 */

export interface SupabaseEnv {
  readonly url: string;
  readonly anonKey: string;
}

function readHttpsUrl(raw: string | undefined): string | null {
  if (!raw) return null;

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    // Not a URL at all. Treat as unconfigured rather than guessing.
    return null;
  }

  if (parsed.protocol !== "https:") return null;

  // Return the parsed form, not the raw input.
  return parsed.origin;
}

/**
 * Returns validated Supabase config, or null when it is absent or unusable.
 * Callers must handle null — there is no "assume it's there" variant.
 */
export function getSupabaseEnv(): SupabaseEnv | null {
  const url = readHttpsUrl(process.env.NEXT_PUBLIC_SUPABASE_URL);
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim();

  if (!url || !anonKey) return null;

  return { url, anonKey };
}

/** True when Supabase is fully configured. Safe to call anywhere. */
export function isSupabaseConfigured(): boolean {
  return getSupabaseEnv() !== null;
}
