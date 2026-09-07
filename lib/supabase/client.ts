"use client";

import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";

import { getSupabaseEnv } from "./env";

/**
 * Browser-side Supabase client, or null when unconfigured.
 *
 * Deliberately a function, not a module-level singleton: instantiating at
 * import time would run during the build, which must succeed with no
 * environment set.
 *
 * Nothing imports this yet. Supabase is wired up but unused.
 */
export function createClient(): SupabaseClient | null {
  const env = getSupabaseEnv();
  if (!env) return null;

  return createBrowserClient(env.url, env.anonKey);
}
