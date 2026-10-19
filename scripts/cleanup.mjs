import pg from "pg";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL est requis pour nettoyer les données expirées.");
if (process.env.DATABASE_SSL !== undefined && !["true", "false"].includes(process.env.DATABASE_SSL)) {
  throw new Error("DATABASE_SSL doit valoir true ou false.");
}

const client = new pg.Client({
  connectionString,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: true } : undefined,
  connectionTimeoutMillis: 3_000,
  statement_timeout: 30_000,
});

try {
  await client.connect();
  await client.query("BEGIN");
  const history = await client.query("DELETE FROM scan_history WHERE expires_at <= now()");
  const quotas = await client.query("DELETE FROM api_rate_limits WHERE expires_at <= now()");
  await client.query("COMMIT");
  console.info(JSON.stringify({ event: "database.cleanup", historyDeleted: history.rowCount, quotasDeleted: quotas.rowCount }));
} catch (error) {
  await client.query("ROLLBACK").catch(() => undefined);
  // Avoid exposing connection details in scheduler logs.
  console.error(JSON.stringify({ event: "database.cleanup_failed", code: error?.code ?? "UNKNOWN" }));
  process.exitCode = 1;
} finally {
  await client.end();
}
