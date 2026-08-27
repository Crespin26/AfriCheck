import { describe, expect, it } from "vitest";
import { baseSecurityHeaders, buildContentSecurityPolicy } from "./security-policy";

describe("buildContentSecurityPolicy", () => {
  it("génère une politique de production stricte liée au nonce", () => {
    const policy = buildContentSecurityPolicy("abc123", false);
    expect(policy).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(policy).toContain("frame-ancestors 'none'");
    expect(policy).toContain("upgrade-insecure-requests");
    expect(policy).not.toContain("'unsafe-inline'");
    expect(policy).not.toContain("'unsafe-eval'");
  });
  it("autorise eval uniquement pour les outils de développement React", () => {
    const policy = buildContentSecurityPolicy("dev", true);
    expect(policy).toContain("'unsafe-eval'");
    expect(policy).not.toContain("upgrade-insecure-requests");
  });
  it("expose toutes les protections défensives de base", () => {
    const names = new Set(baseSecurityHeaders.map(({ key }) => key.toLowerCase()));
    for (const expected of ["x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy"]) expect(names.has(expected)).toBe(true);
  });
});
