import "server-only";
import { createHmac } from "node:crypto";
import type { QueryResultRow } from "pg";
import { databasePool } from "./database";
import { FixedWindowRateLimiter, type RateLimitDecision } from "./rate-limit";

type CounterRow = QueryResultRow & { request_count: number | string };
export type RateLimitQuery = <T extends QueryResultRow>(text: string, values?: unknown[]) => Promise<{ rows: T[] }>;
type Dependencies = { query?: RateLimitQuery; hashKey?: string };

function defaultQuery<T extends QueryResultRow>(text: string, values?: unknown[]) {
  return databasePool().query<T>(text, values);
}

function privacySafeWarning(scope: string): void {
  console.warn(JSON.stringify({ timestamp: new Date().toISOString(), service: "africheck", event: "rate_limit.local_fallback", scope }));
}

export class HybridRateLimiter {
  private readonly local: FixedWindowRateLimiter;

  constructor(private readonly scope: string, private readonly limit: number, private readonly windowMs: number, private readonly dependencies: Dependencies = {}) {
    if (!/^[a-z][a-z0-9._-]{0,63}$/.test(scope)) throw new Error("Scope de rate limiting invalide.");
    this.local = new FixedWindowRateLimiter(limit, windowMs);
  }

  async check(identity: string, now = Date.now()): Promise<RateLimitDecision> {
    const hashKey = this.dependencies.hashKey ?? process.env.LOG_HASH_KEY;
    const databaseEnabled = Boolean(this.dependencies.query || process.env.DATABASE_URL);
    if (!databaseEnabled || !hashKey || Buffer.byteLength(hashKey, "utf8") < 32) return this.local.check(identity, now);
    const identityHash = createHmac("sha256", hashKey).update(`rate-limit:${this.scope}:${identity}`).digest("hex");
    const windowStartMs = Math.floor(now / this.windowMs) * this.windowMs;
    const resetAt = windowStartMs + this.windowMs;
    const query = this.dependencies.query ?? defaultQuery;
    try {
      const { rows } = await query<CounterRow>(
        `WITH cleanup AS (
          DELETE FROM api_rate_limits WHERE expires_at <= now()
        ), counter AS (
          INSERT INTO api_rate_limits (scope, identity_hash, window_start, request_count, expires_at)
          VALUES ($1, $2, $3, 1, $4)
          ON CONFLICT (scope, identity_hash, window_start)
          DO UPDATE SET request_count = api_rate_limits.request_count + 1
          RETURNING request_count
        ) SELECT request_count FROM counter`,
        [this.scope, identityHash, new Date(windowStartMs), new Date(resetAt)],
      );
      const count = Number(rows[0]?.request_count);
      if (!Number.isInteger(count) || count < 1) throw new Error("Compteur PostgreSQL invalide.");
      const allowed = count <= this.limit;
      return { allowed, limit: this.limit, remaining: Math.max(0, this.limit - count), retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((resetAt - now) / 1000)), resetAt };
    } catch {
      privacySafeWarning(this.scope);
      return this.local.check(identity, now);
    }
  }
}
