import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { createDomainChallenge, verifyDomainChallenge } from "@/lib/domain-verification";

vi.mock("@/lib/observability", () => ({ createRequestId: () => "req-proof" }));

beforeEach(() => {
  vi.resetModules();
  process.env.DOMAIN_VERIFICATION_KEY = "k".repeat(32);
  delete process.env.TRUST_PROXY_HEADERS;
});

async function validProof() {
  const secret = "s".repeat(43);
  const subject = createHash("sha256").update(secret).digest("base64url");
  const challenge = createDomainChallenge("example.com", subject, Buffer.from("k".repeat(32)));
  const result = await verifyDomainChallenge({ challenge: challenge.challenge, clientSecret: secret }, Buffer.from("k".repeat(32)), Date.now(), async (url) => ({ status: 200, headers: new Headers(), cookies: [], body: challenge.challenge, finalUrl: url }));
  return { secret, proof: result.proof };
}

describe("POST /api/domains/proof", () => {
  it("revalide une preuve signée et liée au navigateur", async () => {
    const value = await validProof();
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/proof", { method: "POST", body: JSON.stringify({ proof: value.proof, clientSecret: value.secret }) }));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ valid: true, hostname: "example.com" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("refuse une preuve copiée sans le secret associé", async () => {
    const value = await validProof();
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/proof", { method: "POST", body: JSON.stringify({ proof: value.proof, clientSecret: "x".repeat(43) }) }));
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ code: "SUBJECT_MISMATCH", requestId: "req-proof" });
  });
});
