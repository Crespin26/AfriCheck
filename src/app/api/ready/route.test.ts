import { afterEach, describe, expect, it } from "vitest";
import { GET } from "./route";

const originalKey = process.env.LOG_HASH_KEY;

afterEach(() => {
  if (originalKey === undefined) delete process.env.LOG_HASH_KEY;
  else process.env.LOG_HASH_KEY = originalKey;
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
});
