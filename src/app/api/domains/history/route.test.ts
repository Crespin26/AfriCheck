import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { createDomainChallenge, verifyDomainChallenge } from "@/lib/domain-verification";

const listScanHistory = vi.fn(async () => [{ id: "scan-1", scannedAt: "2026-08-27T12:00:00.000Z", score: 82, grade: "B" }]);
vi.mock("@/lib/scan-history", () => ({ listScanHistory }));
vi.mock("@/lib/observability", () => ({ createRequestId: () => "req-history" }));

beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks();
  process.env.DOMAIN_VERIFICATION_KEY = "k".repeat(32);
  process.env.DATABASE_URL = "postgres://user:pass@db.example/africheck";
  delete process.env.TRUST_PROXY_HEADERS;
});

async function ownership() {
  const secret = "s".repeat(43);
  const subject = createHash("sha256").update(secret).digest("base64url");
  const challenge = createDomainChallenge("example.com", subject, Buffer.from("k".repeat(32)));
  const result = await verifyDomainChallenge({ challenge: challenge.challenge, clientSecret: secret }, Buffer.from("k".repeat(32)), Date.now(), async (url) => ({ status: 200, headers: new Headers(), cookies: [], body: challenge.challenge, finalUrl: url }));
  return { proof: result.proof, clientSecret: secret };
}

describe("POST /api/domains/history", () => {
  it("retourne uniquement l’historique du domaine prouvé", async () => {
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/history", { method: "POST", body: JSON.stringify(await ownership()) }));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ hostname: "example.com", history: [{ id: "scan-1", scannedAt: "2026-08-27T12:00:00.000Z", score: 82, grade: "B" }] });
    expect(listScanHistory).toHaveBeenCalledWith("example.com");
  });

  it("ne consulte jamais le dépôt sans base configurée", async () => {
    delete process.env.DATABASE_URL;
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/history", { method: "POST", body: JSON.stringify(await ownership()) }));
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({ code: "HISTORY_DISABLED" });
    expect(listScanHistory).not.toHaveBeenCalled();
  });
});
