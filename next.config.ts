import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Surfaced must build with no environment variables set. Nothing here may
  // read process.env — see lib/supabase/env.ts for how optional config is
  // validated at runtime instead.
};

export default nextConfig;
