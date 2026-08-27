import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/scanner", () => ({ scanWebsite: vi.fn(async (url: string) => ({ url, score: 80 })) }));

beforeEach(() => { vi.resetModules(); delete process.env.TRUST_PROXY_HEADERS; });

describe("POST /api/scan", () => {
  it("refuse un JSON invalide sans exposer l’erreur du parseur", async () => {
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/scan", { method: "POST", body: "{" }));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "Le corps de la requête doit être un JSON valide." });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("refuse une taille déclarée supérieure à 4 Ko", async () => {
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/scan", { method: "POST", headers: { "content-length": "5000" }, body: "{}" }));
    expect(response.status).toBe(413);
  });

  it("retourne 429 et Retry-After après cinq demandes", async () => {
    const { POST } = await import("./route");
    const makeRequest = () => new Request("https://app.test/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: "example.com" }) });
    for (let index = 0; index < 5; index += 1) expect((await POST(makeRequest())).status).toBe(200);
    const blocked = await POST(makeRequest());
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(blocked.headers.get("x-ratelimit-remaining")).toBe("0");
  });
});
