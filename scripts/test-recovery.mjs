import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, open, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { databaseCommand } from "./compose-database.mjs";

const exec = promisify(execFile);
const directory = await mkdtemp(join(tmpdir(), "africheck-recovery-"));
const image = (await readFile("compose.yaml", "utf8")).match(/^\s+image:\s+(postgres:\S+)/m)?.[1];
assert.ok(image, "Image PostgreSQL introuvable dans compose.yaml.");
// A unique Compose project without a persistent volume or host port.
process.env.COMPOSE_FILE = join(directory, "compose.json");
process.env.COMPOSE_PROJECT_NAME = `africheck-recovery-${randomBytes(6).toString("hex")}`;
await writeFile(process.env.COMPOSE_FILE, JSON.stringify({ services: { database: {
  image,
  environment: { POSTGRES_DB: "africheck", POSTGRES_USER: "africheck", POSTGRES_PASSWORD: randomBytes(24).toString("hex") },
  tmpfs: ["/var/lib/postgresql/data"],
  healthcheck: { test: ["CMD-SHELL", "pg_isready -U africheck -d africheck"], interval: "1s", timeout: "5s", retries: 30 },
} } }), { mode: 0o600 });

const compose = (...args) => exec("docker", ["compose", ...args]);
const script = (name, ...args) => exec(process.execPath, [resolve(`scripts/${name}.mjs`), ...args]);
const query = async (database, sql) => (await compose("exec", "-T", "database", "psql", "-v", "ON_ERROR_STOP=1", "-U", "africheck", "-d", database, "-At", "-c", sql)).stdout.trim();
const counts = "SELECT json_build_object('history', (SELECT count(*) FROM scan_history), 'migrations', (SELECT count(*) FROM schema_migrations), 'quotas', (SELECT count(*) FROM api_rate_limits))";

try {
  await compose("up", "--detach", "--wait", "--wait-timeout", "60", "database");
  const migrations = ["001_scan_history.sql", "002_api_rate_limits.sql"];
  const sql = ["CREATE TABLE schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());"];
  for (const name of migrations) {
    sql.push(await readFile(join("migrations", name), "utf8"));
    sql.push(`INSERT INTO schema_migrations (name) VALUES ('${name}');`);
  }
  sql.push("INSERT INTO scan_history (id, hostname, scanned_at, expires_at, score, grade, result) VALUES ('11111111-1111-4111-8111-111111111111', 'recovery.example', now(), now() + interval '1 day', 82, 'B', '{\"restorationTest\":true}');");
  sql.push("INSERT INTO api_rate_limits (scope, identity_hash, window_start, request_count, expires_at) VALUES ('recovery', repeat('a', 64), now(), 1, now() + interval '1 day');");
  const sqlPath = join(directory, "seed.sql");
  await writeFile(sqlPath, sql.join("\n"));
  const input = await open(sqlPath, "r");
  try {
    await databaseCommand(["psql", "-v", "ON_ERROR_STOP=1", "-U", "africheck", "-d", "africheck"], { input: input.fd, output: "ignore" });
  } finally { await input.close(); }

  const archive = join(directory, "recovery.dump");
  await script("backup", archive);
  assert.equal((await stat(archive)).mode & 0o777, 0o600);
  const originalArchive = await readFile(archive);
  await assert.rejects(script("backup", archive));
  assert.deepEqual(await readFile(archive), originalArchive, "L’archive existante a été modifiée.");

  await script("restore", archive, "africheck_restored");
  assert.deepEqual(JSON.parse(await query("africheck_restored", counts)), { history: 1, migrations: 2, quotas: 0 });
  assert.equal(await query("africheck_restored", "SELECT result->>'restorationTest' FROM scan_history"), "true");
  await assert.rejects(script("restore", archive, "africheck_restored"));
  await assert.rejects(script("restore", archive, "africheck"));
  assert.deepEqual(JSON.parse(await query("africheck", counts)), { history: 1, migrations: 2, quotas: 1 });

  const invalid = join(directory, "invalid.dump");
  await writeFile(invalid, "invalid archive");
  await assert.rejects(script("restore", invalid, "invalid_restore"));
  assert.equal(await query("postgres", "SELECT count(*) FROM pg_database WHERE datname = 'invalid_restore'"), "0");
  console.info(JSON.stringify({ event: "database.recovery_test_passed", historyRestored: true, migrationsRestored: true, quotasExcluded: true, existingDataProtected: true }));
} finally {
  try {
    await compose("down", "--volumes", "--remove-orphans");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
