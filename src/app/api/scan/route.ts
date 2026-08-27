import { scanWebsite } from "@/lib/scanner";
import { toPublicError } from "@/lib/errors";
import { FixedWindowRateLimiter, rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";
import { clientFingerprint, createRequestId, logScanEvent } from "@/lib/observability";

const limiter = new FixedWindowRateLimiter(5, 10 * 60 * 1000);
const MAX_REQUEST_BYTES = 4096;

export async function POST(request: Request) {
  const started = Date.now();
  const requestId = createRequestId();
  const identity = requestIdentity(request);
  const fingerprint = clientFingerprint(identity);
  const decision = limiter.check(identity);
  const responseHeaders = { ...rateLimitHeaders(decision), "cache-control": "no-store", "x-request-id": requestId };
  const errorResponse = (error: string, code: string, status: number) => Response.json({ error, code, requestId }, { status, headers: responseHeaders });
  const reject = (error: string, status: number) => {
    logScanEvent({ event: "scan.rejected", requestId, durationMs: Date.now() - started, errorCode: "INVALID_REQUEST", clientFingerprint: fingerprint });
    return errorResponse(error, "INVALID_REQUEST", status);
  };

  if (!decision.allowed) {
    logScanEvent({ event: "scan.rate_limited", requestId, durationMs: Date.now() - started, errorCode: "RATE_LIMITED", clientFingerprint: fingerprint });
    return errorResponse("Trop de diagnostics demandés. Réessayez plus tard.", "RATE_LIMITED", 429);
  }

  try {
    const declaredSize = Number(request.headers.get("content-length") ?? 0);
    if (declaredSize > MAX_REQUEST_BYTES) return reject("La requête est trop volumineuse.", 413);
    const rawBody = await request.text();
    if (Buffer.byteLength(rawBody, "utf8") > MAX_REQUEST_BYTES) return reject("La requête est trop volumineuse.", 413);
    let body: { url?: unknown };
    try { body = JSON.parse(rawBody) as { url?: unknown }; } catch { return reject("Le corps de la requête doit être un JSON valide.", 400); }
    if (typeof body.url !== "string") return reject("Une adresse web est requise.", 400);

    const result = await scanWebsite(body.url);
    logScanEvent({ event: "scan.completed", requestId, durationMs: Date.now() - started, score: result.score, grade: result.grade, clientFingerprint: fingerprint });
    return Response.json(result, { headers: responseHeaders });
  } catch (error) {
    const publicError = toPublicError(error);
    logScanEvent({ event: "scan.failed", requestId, durationMs: Date.now() - started, errorCode: publicError.code, clientFingerprint: fingerprint });
    return errorResponse(publicError.message, publicError.code, publicError.status);
  }
}
