import { createDomainChallenge, domainVerificationKey, toDomainVerificationError } from "@/lib/domain-verification";
import { toPublicError } from "@/lib/errors";
import { createRequestId } from "@/lib/observability";
import { FixedWindowRateLimiter, rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";
import { resolvePublicUrl } from "@/lib/url-safety";

const limiter = new FixedWindowRateLimiter(5, 10 * 60 * 1000);
const MAX_REQUEST_BYTES = 4096;

export async function POST(request: Request) {
  const requestId = createRequestId();
  const decision = limiter.check(requestIdentity(request));
  const headers = { ...rateLimitHeaders(decision), "cache-control": "no-store", "x-request-id": requestId };
  const fail = (message: string, code: string, status: number) => Response.json({ error: message, code, requestId }, { status, headers });
  if (!decision.allowed) return fail("Trop de challenges demandés. Réessayez plus tard.", "RATE_LIMITED", 429);
  try {
    const declaredSize = Number(request.headers.get("content-length") ?? 0);
    if (declaredSize > MAX_REQUEST_BYTES) return fail("La requête est trop volumineuse.", "INVALID_REQUEST", 413);
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_REQUEST_BYTES) return fail("La requête est trop volumineuse.", "INVALID_REQUEST", 413);
    let body: { url?: unknown; subject?: unknown };
    try { body = JSON.parse(raw) as { url?: unknown; subject?: unknown }; }
    catch { return fail("Le corps de la requête doit être un JSON valide.", "INVALID_REQUEST", 400); }
    if (typeof body.url !== "string" || typeof body.subject !== "string") return fail("Une adresse web et un identifiant navigateur sont requis.", "INVALID_REQUEST", 400);
    const result = createDomainChallenge(body.url, body.subject, domainVerificationKey());
    await resolvePublicUrl(new URL(result.verificationUrl));
    return Response.json(result, { status: 201, headers });
  } catch (error) {
    const domainError = toDomainVerificationError(error);
    if (domainError) return fail(domainError.message, domainError.code, domainError.status);
    const publicError = toPublicError(error);
    return fail(publicError.message, publicError.code, publicError.status);
  }
}
