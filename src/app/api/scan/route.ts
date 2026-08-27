import { scanWebsite } from "@/lib/scanner";
import { FixedWindowRateLimiter, rateLimitHeaders, requestIdentity } from "@/lib/rate-limit";

const limiter = new FixedWindowRateLimiter(5, 10 * 60 * 1000);
const MAX_REQUEST_BYTES = 4096;

export async function POST(request: Request) {
  const decision = limiter.check(requestIdentity(request));
  const limitHeaders = rateLimitHeaders(decision);
  const json = (error: string, status: number) => Response.json({ error }, { status, headers: { ...limitHeaders, "cache-control": "no-store" } });
  if (!decision.allowed) return json("Trop de diagnostics demandés. Réessayez plus tard.", 429);
  try {
    const declaredSize = Number(request.headers.get("content-length") ?? 0);
    if (declaredSize > MAX_REQUEST_BYTES) return json("La requête est trop volumineuse.", 413);
    const rawBody = await request.text();
    if (Buffer.byteLength(rawBody, "utf8") > MAX_REQUEST_BYTES) return json("La requête est trop volumineuse.", 413);
    let body: { url?: unknown };
    try { body = JSON.parse(rawBody) as { url?: unknown }; } catch { return json("Le corps de la requête doit être un JSON valide.", 400); }
    if (typeof body.url !== "string") return json("Une adresse web est requise.", 400);
    const result = await scanWebsite(body.url);
    return Response.json(result, { headers: { ...limitHeaders, "cache-control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Le diagnostic a échoué.";
    const safeMessage = /fetch failed|ENOTFOUND|timeout|aborted/i.test(message) ? "Impossible de joindre ce site pour le moment." : message;
    return Response.json({ error: safeMessage }, { status: 400, headers: { ...limitHeaders, "cache-control": "no-store" } });
  }
}
