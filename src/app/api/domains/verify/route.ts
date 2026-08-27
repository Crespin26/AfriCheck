import { domainVerificationKey, toDomainVerificationError, verifyDomainChallenge } from "@/lib/domain-verification";
import { toPublicError } from "@/lib/errors";
import { createRequestId } from "@/lib/observability";
import { rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";
import { HybridRateLimiter } from "@/lib/distributed-rate-limit";

const limiter = new HybridRateLimiter("domain-verify", 10, 10 * 60 * 1000);
const MAX_REQUEST_BYTES = 8192;

export async function POST(request: Request) {
  const requestId = createRequestId();
  const decision = await limiter.check(requestIdentity(request));
  const headers = { ...rateLimitHeaders(decision), "cache-control": "no-store", "x-request-id": requestId };
  const fail = (message: string, code: string, status: number) => Response.json({ error: message, code, requestId }, { status, headers });
  if (!decision.allowed) return fail("Trop de vérifications demandées. Réessayez plus tard.", "RATE_LIMITED", 429);
  try {
    const declaredSize = Number(request.headers.get("content-length") ?? 0);
    if (declaredSize > MAX_REQUEST_BYTES) return fail("La requête est trop volumineuse.", "INVALID_REQUEST", 413);
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_REQUEST_BYTES) return fail("La requête est trop volumineuse.", "INVALID_REQUEST", 413);
    let body: { challenge?: unknown; clientSecret?: unknown };
    try { body = JSON.parse(raw) as { challenge?: unknown; clientSecret?: unknown }; }
    catch { return fail("Le corps de la requête doit être un JSON valide.", "INVALID_REQUEST", 400); }
    if (typeof body.challenge !== "string" || typeof body.clientSecret !== "string") return fail("Le challenge et le secret navigateur sont requis.", "INVALID_REQUEST", 400);
    const result = await verifyDomainChallenge({ challenge: body.challenge, clientSecret: body.clientSecret }, domainVerificationKey());
    return Response.json(result, { headers });
  } catch (error) {
    const domainError = toDomainVerificationError(error);
    if (domainError) return fail(domainError.message, domainError.code, domainError.status);
    const publicError = toPublicError(error);
    return fail(publicError.message, publicError.code, publicError.status);
  }
}
