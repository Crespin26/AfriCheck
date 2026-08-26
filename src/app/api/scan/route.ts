import { scanWebsite } from "@/lib/scanner";

export async function POST(request: Request) {
  try {
    const body = await request.json() as { url?: unknown };
    if (typeof body.url !== "string") return Response.json({ error: "Une adresse web est requise." }, { status: 400 });
    const result = await scanWebsite(body.url);
    return Response.json(result, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Le diagnostic a échoué.";
    const safeMessage = /fetch failed|ENOTFOUND|timeout|aborted/i.test(message) ? "Impossible de joindre ce site pour le moment." : message;
    return Response.json({ error: safeMessage }, { status: 400, headers: { "cache-control": "no-store" } });
  }
}
