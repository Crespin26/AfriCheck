import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { databasePool } from "./database";
import { listScanHistory, saveScanHistory } from "./scan-history";
import { HybridRateLimiter } from "./distributed-rate-limit";
import type { ScanResult } from "./types";
import { GET as readinessRoute } from "@/app/api/ready/route";

const describeWithDatabase = process.env.DATABASE_URL ? describe : describe.skip;
const hostname = "history-integration.example";
const rateLimitScope = "integration-scan";
const cleanupHostname = "cleanup-history-integration.example";
const cleanupScope = "integration-cleanup";
const result: ScanResult = { url: `https://${hostname}/`, finalUrl: `https://${hostname}/`, scannedAt: new Date().toISOString(), durationMs: 200, score: 82, grade: "B", findings: [] };

describeWithDatabase("historique PostgreSQL", () => {
  beforeAll(async () => {
    await databasePool().query("DELETE FROM scan_history WHERE hostname = ANY($1)", [[hostname, cleanupHostname]]);
    await databasePool().query("DELETE FROM api_rate_limits WHERE scope = ANY($1)", [[rateLimitScope, cleanupScope]]);
  });
  afterAll(async () => {
    await databasePool().query("DELETE FROM scan_history WHERE hostname = ANY($1)", [[hostname, cleanupHostname]]);
    await databasePool().query("DELETE FROM api_rate_limits WHERE scope = ANY($1)", [[rateLimitScope, cleanupScope]]);
    await databasePool().end();
    delete globalThis.africheckDatabasePool;
  });

  it("écrit et relit un scan dans le schéma migré", async () => {
    const id = await saveScanHistory(hostname, result);
    await expect(listScanHistory(hostname)).resolves.toEqual([{ id, scannedAt: result.scannedAt, score: 82, grade: "B" }]);
    const stored = await databasePool().query<{ result: ScanResult }>("SELECT result FROM scan_history WHERE id = $1", [id]);
    expect(stored.rows[0].result).toEqual(result);
  });

  it("ne crée aucune colonne pour les secrets ou les preuves", async () => {
    const columns = await databasePool().query<{ column_name: string }>("SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'scan_history'");
    expect(columns.rows.map((row) => row.column_name)).not.toEqual(expect.arrayContaining(["client_secret", "proof", "ip_address", "subject"]));
  });

  it("compte atomiquement les scans sans stocker l’identité réseau", async () => {
    const limiter = new HybridRateLimiter(rateLimitScope, 2, 60_000, { hashKey: "k".repeat(32) });
    const now = Date.now();
    expect((await limiter.check("203.0.113.10", now)).allowed).toBe(true);
    expect((await limiter.check("203.0.113.10", now)).allowed).toBe(true);
    expect((await limiter.check("203.0.113.10", now)).allowed).toBe(false);

    const stored = await databasePool().query<{ identity_hash: string; request_count: number }>(
      "SELECT identity_hash, request_count FROM api_rate_limits WHERE scope = $1",
      [rateLimitScope],
    );
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0]).toMatchObject({ request_count: 3 });
    expect(stored.rows[0].identity_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(stored.rows[0].identity_hash).not.toContain("203.0.113.10");
  });

  it("nettoie les données expirées sans toucher aux rapports et quotas actifs", async () => {
    const expiredId = randomUUID();
    await saveScanHistory(cleanupHostname, { ...result, finalUrl: `https://${cleanupHostname}/` });
    await databasePool().query(
      "INSERT INTO api_rate_limits (scope, identity_hash, window_start, request_count, expires_at) VALUES ($1, $2, now(), 3, now() + interval '1 day')",
      [cleanupScope, "b".repeat(64)],
    );
    await databasePool().query(
      "INSERT INTO scan_history (id, hostname, scanned_at, expires_at, score, grade, result) VALUES ($1, $2, now() - interval '2 days', now() - interval '1 day', 50, 'D', '{}'::jsonb)",
      [expiredId, cleanupHostname],
    );
    await databasePool().query(
      "INSERT INTO api_rate_limits (scope, identity_hash, window_start, request_count, expires_at) VALUES ($1, $2, now() - interval '2 days', 1, now() - interval '1 day')",
      [cleanupScope, "a".repeat(64)],
    );
    const run = () => promisify(execFile)(process.execPath, ["scripts/cleanup.mjs"], { env: process.env });
    const { stdout } = await run();
    expect(JSON.parse(stdout)).toMatchObject({ event: "database.cleanup", historyDeleted: 1, quotasDeleted: 1 });
    expect((await databasePool().query("SELECT id FROM scan_history WHERE id = $1", [expiredId])).rows).toHaveLength(0);
    expect(await listScanHistory(cleanupHostname)).toHaveLength(1);
    expect((await databasePool().query("SELECT request_count FROM api_rate_limits WHERE scope = $1", [cleanupScope])).rows).toEqual([{ request_count: 3 }]);
    expect(JSON.parse((await run()).stdout)).toMatchObject({ historyDeleted: 0, quotasDeleted: 0 });
  });

  it("conserve la méthode v2 pour distinguer les nouveaux scores des anciens", async () => {
    const id = await saveScanHistory(hostname, { ...result, scoringVersion: 2 });
    expect((await listScanHistory(hostname)).find((item) => item.id === id)).toMatchObject({ scoringVersion: 2 });
  });

  it("déclare l’instance prête lorsque le schéma répond", async () => {
    const response = await readinessRoute();
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ status: "ready", checks: { history: "ok" } });
  });
});
