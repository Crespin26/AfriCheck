import { databaseConfiguration, DatabaseConfigurationError } from "@/lib/database";
import { domainVerificationKey, toDomainVerificationError, verifyOwnershipProof } from "@/lib/domain-verification";
import { createRequestId } from "@/lib/observability";
import { rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";
import { HybridRateLimiter } from "@/lib/distributed-rate-limit";
import { listScanHistory } from "@/lib/scan-history";

const limiter = new HybridRateLimiter("domain-history", 20, 10 * 60 * 1000);
const MAX_REQUEST_BYTES = 8192;

export async function POST(request: Request) {
  const requestId = createRequestId();
  const decision = await limiter.check(requestIdentity(request));
  const headers = { ...rateLimitHeaders(decision), "cache-control": "no-store", "x-request-id": requestId };
  const fail = (message: string, code: string, status: number) => Response.json({ error: message, code, requestId }, { status, headers });
  if (!decision.allowed) return fail("Trop de consultations demandées. Réessayez plus tard.", "RATE_LIMITED", 429);
  try {
    const declaredSize = Number(request.headers.get("content-length") ?? 0);
    if (declaredSize > MAX_REQUEST_BYTES) return fail("La requête est trop volumineuse.", "INVALID_REQUEST", 413);
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_REQUEST_BYTES) return fail("La requête est trop volumineuse.", "INVALID_REQUEST", 413);
    let body: { proof?: unknown; clientSecret?: unknown };
    try { body = JSON.parse(raw) as { proof?: unknown; clientSecret?: unknown }; }
    catch { return fail("Le corps de la requête doit être un JSON valide.", "INVALID_REQUEST", 400); }
    if (typeof body.proof !== "string" || typeof body.clientSecret !== "string") return fail("La preuve et le secret navigateur sont requis.", "INVALID_REQUEST", 400);
    databaseConfiguration();
    const verified = verifyOwnershipProof(body.proof, body.clientSecret, domainVerificationKey());
    const history = await listScanHistory(verified.hostname);
    return Response.json({ hostname: verified.hostname, history }, { headers });
  } catch (error) {
    const domainError = toDomainVerificationError(error);
    if (domainError) return fail(domainError.message, domainError.code, domainError.status);
    if (error instanceof DatabaseConfigurationError && error.code === "DATABASE_DISABLED") return fail("L’historique n’est pas activé sur cette instance.", "HISTORY_DISABLED", 503);
    return fail("L’historique est temporairement indisponible.", "HISTORY_UNAVAILABLE", 503);
  }
}
