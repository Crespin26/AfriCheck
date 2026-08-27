import type { NextConfig } from "next";
import { baseSecurityHeaders } from "./src/lib/security-policy";

const nextConfig: NextConfig = {
  turbopack: {
    root: process.cwd(),
  },
  async headers() {
    const headers: Array<{ key: string; value: string }> = [...baseSecurityHeaders];
    if (process.env.NODE_ENV === "production") headers.push({ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" });
    return [{ source: "/:path*", headers }];
  },
};

export default nextConfig;
