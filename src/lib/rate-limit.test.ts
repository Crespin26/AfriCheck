import { afterEach, describe, expect, it } from "vitest";
import { FixedWindowRateLimiter, rateLimitHeaders, requestIdentity } from "./rate-limit";

afterEach(() => { delete process.env.TRUST_PROXY_HEADERS; });

describe("FixedWindowRateLimiter", () => {
  it("autorise jusqu’à la limite puis indique le délai", () => {
    const limiter = new FixedWindowRateLimiter(2, 10_000);
    expect(limiter.check("client", 1_000)).toMatchObject({ allowed: true, remaining: 1 });
    expect(limiter.check("client", 1_100)).toMatchObject({ allowed: true, remaining: 0 });
    expect(limiter.check("client", 2_000)).toMatchObject({ allowed: false, remaining: 0, retryAfterSeconds: 9 });
  });
  it("réinitialise une fenêtre expirée et sépare les clients", () => {
    const limiter = new FixedWindowRateLimiter(1, 1_000);
    expect(limiter.check("a", 0).allowed).toBe(true);
    expect(limiter.check("a", 500).allowed).toBe(false);
    expect(limiter.check("b", 500).allowed).toBe(true);
    expect(limiter.check("a", 1_000).allowed).toBe(true);
  });
  it("rejette une configuration incorrecte", () => expect(() => new FixedWindowRateLimiter(0, 1_000)).toThrow());
});

describe("requestIdentity", () => {
  it("ignore les en-têtes proxy par défaut", () => expect(requestIdentity(new Request("https://app.test", { headers: { "x-forwarded-for": "1.2.3.4" } }))).toBe("shared"));
  it("accepte le premier client uniquement quand le proxy est approuvé", () => {
    process.env.TRUST_PROXY_HEADERS = "true";
    expect(requestIdentity(new Request("https://app.test", { headers: { "x-forwarded-for": "1.2.3.4, 10.0.0.1" } }))).toBe("1.2.3.4");
  });
  it("produit les en-têtes standards attendus", () => {
    const headers = new Headers(rateLimitHeaders({ allowed: false, limit: 5, remaining: 0, retryAfterSeconds: 30, resetAt: 31_000 }));
    expect(headers.get("retry-after")).toBe("30"); expect(headers.get("x-ratelimit-limit")).toBe("5");
  });
});
