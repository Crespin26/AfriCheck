import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

const fetchWebsite = vi.fn();
vi.mock("@/lib/transport", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/lib/transport")>()), fetchWebsite }));
vi.mock("@/lib/observability", () => ({ createRequestId: () => "req-verify" }));

beforeEach(() => {
  vi.resetModules();
  fetchWebsite.mockReset();
  process.env.DOMAIN_VERIFICATION_KEY = "k".repeat(32);
  delete process.env.TRUST_PROXY_HEADERS;
});

describe("POST /api/domains/verify", () => {
  it("retourne une preuve lorsque le fichier public contient le challenge", async () => {
    const { createDomainChallenge } = await import("@/lib/domain-verification");
    const secret = "s".repeat(43);
    const subject = createHash("sha256").update(secret).digest("base64url");
    const created = createDomainChallenge("example.com", subject, Buffer.from("k".repeat(32)));
    fetchWebsite.mockResolvedValue({ status: 200, headers: new Headers(), cookies: [], body: created.challenge, finalUrl: new URL(created.verificationUrl) });
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/verify", { method: "POST", body: JSON.stringify({ challenge: created.challenge, clientSecret: secret }) }));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ hostname: "example.com" });
    expect(fetchWebsite).toHaveBeenCalledWith(new URL(created.verificationUrl), { maxBodyBytes: 4096, timeoutMs: 8000, maxRedirects: 2 });
  });

  it("ne divulgue pas le contenu attendu en cas de fichier incorrect", async () => {
    const { createDomainChallenge } = await import("@/lib/domain-verification");
    const secret = "s".repeat(43);
    const subject = createHash("sha256").update(secret).digest("base64url");
    const created = createDomainChallenge("example.com", subject, Buffer.from("k".repeat(32)));
    fetchWebsite.mockResolvedValue({ status: 200, headers: new Headers(), cookies: [], body: "autre contenu", finalUrl: new URL(created.verificationUrl) });
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/verify", { method: "POST", body: JSON.stringify({ challenge: created.challenge, clientSecret: secret }) }));
    expect(response.status).toBe(422);
    const body = await response.json();
    expect(body).toMatchObject({ code: "VERIFICATION_FILE_MISMATCH", requestId: "req-verify" });
    expect(JSON.stringify(body)).not.toContain(created.challenge);
  });
});
