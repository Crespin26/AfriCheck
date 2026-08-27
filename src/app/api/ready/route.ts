import { readiness } from "@/lib/health";
import { databasePool } from "@/lib/database";

export async function GET() {
  let result = readiness();
  if (result.ready && result.checks.history === "ok") {
    try { await databasePool().query("SELECT 1 FROM scan_history, api_rate_limits LIMIT 1"); }
    catch { result = { ready: false, checks: { ...result.checks, history: "error" } }; }
  }
  return Response.json({ status: result.ready ? "ready" : "not_ready", checks: result.checks }, { status: result.ready ? 200 : 503, headers: { "cache-control": "no-store" } });
}
