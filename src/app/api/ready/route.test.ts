import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GET } from "./route";

const { databaseQuery } = vi.hoisted(() => ({ databaseQuery: vi.fn(async () => ({ rows: [] })) }));
vi.mock("@/lib/database", () => ({ databasePool: () => ({ query: databaseQuery }) }));

const originalKey = process.env.LOG_HASH_KEY;
const originalDomainKey = process.env.DOMAIN_VERIFICATION_KEY;
const originalDatabaseUrl = process.env.DATABASE_URL;
const originalDatabaseSsl = process.env.DATABASE_SSL;

beforeEach(() => { databaseQuery.mockResolvedValue({ rows: [] }); });

afterEach(() => {
  if (originalKey === undefined) delete process.env.LOG_HASH_KEY;
  else process.env.LOG_HASH_KEY = originalKey;
  if (originalDomainKey === undefined) delete process.env.DOMAIN_VERIFICATION_KEY;
  else process.env.DOMAIN_VERIFICATION_KEY = originalDomainKey;
  if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalDatabaseUrl;
  if (originalDatabaseSsl === undefined) delete process.env.DATABASE_SSL;
  else process.env.DATABASE_SSL = originalDatabaseSsl;
});

describe("GET /api/ready", () => {
  it("répond ready lorsque le runtime est correctement configuré", async () => {
    delete process.env.LOG_HASH_KEY;
    const response = await GET();
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ status: "ready" });
  });
  it("retire l’instance du trafic quand la configuration est faible", async () => {
    process.env.LOG_HASH_KEY = "short";
    const response = await GET();
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({ status: "not_ready", checks: { configuration: "error" } });
  });
  it("retire l’instance du trafic quand la clé de domaine est faible", async () => {
    process.env.DOMAIN_VERIFICATION_KEY = "short";
    const response = await GET();
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({ status: "not_ready", checks: { domainVerification: "error" } });
  });
  it("retire l’instance du trafic lorsque le schéma PostgreSQL ne répond pas", async () => {
    process.env.DATABASE_URL = "postgres://user:pass@db.example/africheck";
    databaseQuery.mockRejectedValueOnce(new Error("connection refused"));
    const response = await GET();
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({ status: "not_ready", checks: { history: "error" } });
  });
});
