import { isIP } from "node:net";

export type RateLimitDecision = { allowed: boolean; limit: number; remaining: number; retryAfterSeconds: number; resetAt: number; };

type Entry = { count: number; resetAt: number };

export class FixedWindowRateLimiter {
  private readonly entries = new Map<string, Entry>();
  private operations = 0;

  constructor(private readonly limit: number, private readonly windowMs: number) {
    if (!Number.isInteger(limit) || limit < 1 || !Number.isFinite(windowMs) || windowMs < 1) throw new Error("Configuration de rate limiting invalide.");
  }

  check(key: string, now = Date.now()): RateLimitDecision {
    if (++this.operations % 100 === 0) this.prune(now);
    const current = this.entries.get(key);
    const entry = !current || current.resetAt <= now ? { count: 0, resetAt: now + this.windowMs } : current;
    entry.count += 1;
    this.entries.set(key, entry);
    const allowed = entry.count <= this.limit;
    return { allowed, limit: this.limit, remaining: Math.max(0, this.limit - entry.count), retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((entry.resetAt - now) / 1000)), resetAt: entry.resetAt };
  }

  prune(now = Date.now()): void {
    for (const [key, entry] of this.entries) if (entry.resetAt <= now) this.entries.delete(key);
  }
}

export function requestIdentity(request: Request): string {
  if (process.env.TRUST_PROXY_HEADERS !== "true") return "shared";
  const header = process.env.CLIENT_IP_HEADER ?? "x-forwarded-for";
  if (!["x-forwarded-for", "cf-connecting-ip", "x-vercel-forwarded-for"].includes(header)) return "unknown";
  const raw = request.headers.get(header);
  const candidate = (header === "x-forwarded-for" ? raw?.split(",")[0] : raw)?.trim();
  const version = isIP(candidate ?? "");
  if (!candidate || !version) return "unknown";
  if (version === 4) return candidate;
  try { return new URL(`http://[${candidate}]/`).hostname.slice(1, -1); }
  catch { return "unknown"; }
}

export function rateLimitHeaders(decision: RateLimitDecision): HeadersInit {
  return { "x-ratelimit-limit": String(decision.limit), "x-ratelimit-remaining": String(decision.remaining), "x-ratelimit-reset": String(Math.ceil(decision.resetAt / 1000)), ...(decision.retryAfterSeconds ? { "retry-after": String(decision.retryAfterSeconds) } : {}) };
}
