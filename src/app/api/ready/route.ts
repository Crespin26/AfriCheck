import { readiness } from "@/lib/health";

export async function GET() {
  const result = readiness();
  return Response.json({ status: result.ready ? "ready" : "not_ready", checks: result.checks }, { status: result.ready ? 200 : 503, headers: { "cache-control": "no-store" } });
}
