import { generateReportPdf, parseReportInput, type ReportInput } from "@/lib/pdf-report";
import { FixedWindowRateLimiter, rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";
import { createRequestId } from "@/lib/observability";
import { displayHostname } from "@/lib/report";

const limiter = new FixedWindowRateLimiter(10, 10 * 60 * 1000);
const MAX_REQUEST_BYTES = 65_536;

export async function POST(request: Request) {
  const requestId = createRequestId();
  const decision = limiter.check(requestIdentity(request));
  const headers = { ...rateLimitHeaders(decision), "cache-control": "no-store", "x-request-id": requestId };
  const error = (message: string, status: number) => Response.json({ error: message, code: "INVALID_REPORT", requestId }, { status, headers });
  if (!decision.allowed) return Response.json({ error: "Trop d’exports demandés. Réessayez plus tard.", code: "RATE_LIMITED", requestId }, { status: 429, headers });
  try {
    const declaredSize = Number(request.headers.get("content-length") ?? 0);
    if (declaredSize > MAX_REQUEST_BYTES) return error("Les données du rapport sont trop volumineuses.", 413);
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_REQUEST_BYTES) return error("Les données du rapport sont trop volumineuses.", 413);
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { return error("Les données du rapport sont invalides.", 400); }
    let input: ReportInput;
    try { input = parseReportInput(parsed); } catch { return error("Les données du rapport sont invalides.", 400); }
    let pdf: Uint8Array;
    try { pdf = await generateReportPdf(input); } catch { return Response.json({ error: "Le rapport ne peut pas être généré pour le moment.", code: "REPORT_GENERATION_FAILED", requestId }, { status: 500, headers }); }
    const date = input.scannedAt.slice(0, 10);
    const host = displayHostname(input.finalUrl).replace(/[^a-z0-9.-]+/gi, "-").slice(0, 80);
    return new Response(Buffer.from(pdf), { status: 200, headers: { ...headers, "content-type": "application/pdf", "content-disposition": `attachment; filename="africheck-${host}-${date}.pdf"`, "x-content-type-options": "nosniff" } });
  } catch {
    return error("Les données du rapport sont invalides.", 400);
  }
}
