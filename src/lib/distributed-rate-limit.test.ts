import { describe, expect, it, vi } from "vitest";
import { HybridRateLimiter, type RateLimitQuery } from "./distributed-rate-limit";

describe("HybridRateLimiter", () => {
  it("utilise un compteur PostgreSQL atomique et ne transmet jamais l’identité brute", async () => {
    let count = 0;
    const query = vi.fn(async () => ({ rows: [{ request_count: ++count }] })) as unknown as RateLimitQuery;
    const limiter = new HybridRateLimiter("scan", 2, 60_000, { query, hashKey: "k".repeat(32) });
    expect((await limiter.check("203.0.113.10", 120_000)).allowed).toBe(true);
    expect((await limiter.check("203.0.113.10", 120_001)).allowed).toBe(true);
    const blocked = await limiter.check("203.0.113.10", 120_002);
    expect(blocked).toMatchObject({ allowed: false, remaining: 0, retryAfterSeconds: 60 });
    const serializedCalls = JSON.stringify(vi.mocked(query).mock.calls);
    expect(serializedCalls).not.toContain("203.0.113.10");
    expect(vi.mocked(query).mock.calls[0][1]?.[1]).toMatch(/^[a-f0-9]{64}$/);
  });

  it("isole les fenêtres fixes et calcule leur réinitialisation", async () => {
    const query = vi.fn(async () => ({ rows: [{ request_count: 1 }] })) as unknown as RateLimitQuery;
    const limiter = new HybridRateLimiter("scan", 5, 60_000, { query, hashKey: "k".repeat(32) });
    const decision = await limiter.check("client", 125_000);
    expect(decision).toEqual({ allowed: true, limit: 5, remaining: 4, retryAfterSeconds: 0, resetAt: 180_000 });
    expect(vi.mocked(query).mock.calls[0][1]?.slice(2)).toEqual([new Date(120_000), new Date(180_000)]);
  });

  it("sépare les pseudonymes entre les endpoints", async () => {
    const query = vi.fn(async () => ({ rows: [{ request_count: 1 }] })) as unknown as RateLimitQuery;
    const dependencies = { query, hashKey: "k".repeat(32) };
    await new HybridRateLimiter("scan", 5, 60_000, dependencies).check("client", 120_000);
    await new HybridRateLimiter("report", 5, 60_000, dependencies).check("client", 120_000);
    expect(vi.mocked(query).mock.calls[0][1]?.[1]).not.toBe(vi.mocked(query).mock.calls[1][1]?.[1]);
  });

  it("se replie localement sans clé ou lorsque PostgreSQL échoue", async () => {
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const failedQuery = vi.fn(async () => { throw new Error("database unavailable"); }) as unknown as RateLimitQuery;
    const withoutKey = new HybridRateLimiter("scan", 1, 60_000, { query: failedQuery, hashKey: "short" });
    expect((await withoutKey.check("client", 0)).allowed).toBe(true);
    expect(failedQuery).not.toHaveBeenCalled();
    const withFailure = new HybridRateLimiter("scan", 1, 60_000, { query: failedQuery, hashKey: "k".repeat(32) });
    expect((await withFailure.check("client", 0)).allowed).toBe(true);
    expect((await withFailure.check("client", 1)).allowed).toBe(false);
    expect(warning).toHaveBeenCalledWith(expect.not.stringContaining("client"));
    warning.mockRestore();
  });
});
