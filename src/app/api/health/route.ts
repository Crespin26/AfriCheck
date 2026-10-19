/**
 * Confirme que le serveur répond, sans vérifier les services externes.
 */
export async function GET() {
  return Response.json(
    { status: "ok" },
    { headers: { "cache-control": "no-store" } },
  );
}
