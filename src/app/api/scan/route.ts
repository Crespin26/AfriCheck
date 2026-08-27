import { scanWebsite } from "@/lib/scanner";
import { toPublicError } from "@/lib/errors";
import { rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";
import { HybridRateLimiter } from "@/lib/distributed-rate-limit";
import { clientFingerprint, createRequestId, logScanEvent } from "@/lib/observability";
import { DomainVerificationError, domainVerificationKey, toDomainVerificationError, verifyOwnershipProof } from "@/lib/domain-verification";
import { normalizeUrl } from "@/lib/url-safety";
import { saveScanHistory } from "@/lib/scan-history";
import { DatabaseConfigurationError } from "@/lib/database";
import { ConcurrencyGate, scanConcurrencyLimit } from "@/lib/concurrency-gate";

const limiter = new HybridRateLimiter("scan", 5, 10 * 60 * 1000);
const scanGate = new ConcurrencyGate(scanConcurrencyLimit());
const MAX_REQUEST_BYTES = 4096;

export async function POST(request: Request) {
  const started = Date.now();
  const requestId = createRequestId();
  const identity = requestIdentity(request);
  const fingerprint = clientFingerprint(identity);
  const decision = await limiter.check(identity);
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
    let body: { url?: unknown; ownership?: unknown };
    try { body = JSON.parse(rawBody) as { url?: unknown; ownership?: unknown }; } catch { return reject("Le corps de la requête doit être un JSON valide.", 400); }
    if (typeof body.url !== "string") return reject("Une adresse web est requise.", 400);

    let verifiedHostname: string | undefined;
    if (body.ownership !== undefined) {
      if (!body.ownership || typeof body.ownership !== "object") return reject("La preuve de domaine est invalide.", 400);
      const ownership = body.ownership as { proof?: unknown; clientSecret?: unknown };
      if (typeof ownership.proof !== "string" || typeof ownership.clientSecret !== "string") return reject("La preuve de domaine est invalide.", 400);
      verifiedHostname = verifyOwnershipProof(ownership.proof, ownership.clientSecret, domainVerificationKey()).hostname;
      if (normalizeUrl(body.url).hostname !== verifiedHostname) throw new DomainVerificationError("DOMAIN_MISMATCH");
    }

    const release = scanGate.tryAcquire();
    if (!release) {
      logScanEvent({ event: "scan.busy", requestId, durationMs: Date.now() - started, errorCode: "SCAN_BUSY", clientFingerprint: fingerprint });
      return Response.json(
        { error: "Le scanner est temporairement occupé. Réessayez dans quelques secondes.", code: "SCAN_BUSY", requestId },
        { status: 503, headers: { ...responseHeaders, "retry-after": "5" } },
      );
    }
    let result: Awaited<ReturnType<typeof scanWebsite>>;
    try { result = await scanWebsite(body.url); }
    finally { release(); }
    let history: { saved: boolean; id?: string; code?: "HISTORY_DISABLED" | "HISTORY_UNAVAILABLE" | "DOMAIN_MISMATCH" } | undefined;
    if (verifiedHostname) {
      if (new URL(result.finalUrl).hostname !== verifiedHostname) history = { saved: false, code: "DOMAIN_MISMATCH" };
      else {
        try { history = { saved: true, id: await saveScanHistory(verifiedHostname, result) }; }
        catch (historyError) {
          history = { saved: false, code: historyError instanceof DatabaseConfigurationError && historyError.code === "DATABASE_DISABLED" ? "HISTORY_DISABLED" : "HISTORY_UNAVAILABLE" };
        }
      }
    }
    logScanEvent({ event: "scan.completed", requestId, durationMs: Date.now() - started, score: result.score, grade: result.grade, clientFingerprint: fingerprint, historySaved: history?.saved, historyError: history?.code });
    return Response.json({ ...result, ...(history ? { history } : {}) }, { headers: responseHeaders });
  } catch (error) {
    const domainError = toDomainVerificationError(error);
    if (domainError) {
      logScanEvent({ event: "scan.failed", requestId, durationMs: Date.now() - started, errorCode: "INVALID_REQUEST", clientFingerprint: fingerprint });
      return errorResponse(domainError.message, domainError.code, domainError.status);
    }
    const publicError = toPublicError(error);
    logScanEvent({ event: "scan.failed", requestId, durationMs: Date.now() - started, errorCode: publicError.code, clientFingerprint: fingerprint });
    return errorResponse(publicError.message, publicError.code, publicError.status);
  }
}
