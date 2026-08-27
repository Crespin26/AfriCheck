import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL est requis pour exécuter les migrations.");
if (process.env.DATABASE_SSL !== undefined && !["true", "false"].includes(process.env.DATABASE_SSL)) throw new Error("DATABASE_SSL doit valoir true ou false.");

const client = new pg.Client({ connectionString, ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: true } : undefined });
const migrationsDirectory = path.resolve("migrations");

await client.connect();
try {
  await client.query("SELECT pg_advisory_lock($1)", [1_947_426_311]);
  await client.query("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  const applied = new Set((await client.query("SELECT name FROM schema_migrations")).rows.map((row) => row.name));
  const files = (await readdir(migrationsDirectory)).filter((name) => /^\d+_[a-z0-9_]+\.sql$/.test(name)).sort();
  for (const name of files) {
    if (applied.has(name)) continue;
    const sql = await readFile(path.join(migrationsDirectory, name), "utf8");
    await client.query("BEGIN");
    try {
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [name]);
      await client.query("COMMIT");
      console.info(`Migration appliquée : ${name}`);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  }
} finally {
  await client.query("SELECT pg_advisory_unlock($1)", [1_947_426_311]).catch(() => undefined);
  await client.end();
}
