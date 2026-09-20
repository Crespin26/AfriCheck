import { createDomainChallenge, domainVerificationKey, toDomainVerificationError } from "@/lib/domain-verification";
import { toPublicError } from "@/lib/errors";
import { createRequestId } from "@/lib/observability";
import { rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";
import { HybridRateLimiter } from "@/lib/distributed-rate-limit";
import { readJsonBody, RequestBodyError } from "@/lib/request-body";
import { resolvePublicUrl } from "@/lib/url-safety";

const limiter = new HybridRateLimiter("domain-challenge", 5, 10 * 60 * 1000);
const MAX_REQUEST_BYTES = 4096;

export async function POST(request: Request) {
  const requestId = createRequestId();
  const decision = await limiter.check(requestIdentity(request));
  const headers = { ...rateLimitHeaders(decision), "cache-control": "no-store", "x-request-id": requestId };
  const fail = (message: string, code: string, status: number) => Response.json({ error: message, code, requestId }, { status, headers });
  if (!decision.allowed) return fail("Trop de challenges demandés. Réessayez plus tard.", "RATE_LIMITED", 429);
  try {
    let body: { url?: unknown; subject?: unknown };
    try { body = await readJsonBody(request, MAX_REQUEST_BYTES); }
    catch (error) {
      if (error instanceof RequestBodyError && error.code === "TOO_LARGE") return fail("La requête est trop volumineuse.", "INVALID_REQUEST", 413);
      return fail("Le corps de la requête doit être un JSON valide.", "INVALID_REQUEST", 400);
    }
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
