import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

const resolvePublicUrl = vi.fn(async () => ({ address: "93.184.216.34", family: 4 }));
vi.mock("@/lib/url-safety", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/lib/url-safety")>()), resolvePublicUrl }));
vi.mock("@/lib/observability", () => ({ createRequestId: () => "req-domain" }));

beforeEach(() => {
  vi.resetModules();
  resolvePublicUrl.mockClear();
  process.env.DOMAIN_VERIFICATION_KEY = "k".repeat(32);
  delete process.env.TRUST_PROXY_HEADERS;
});

describe("POST /api/domains/challenge", () => {
  it("crée un challenge uniquement pour une cible publique", async () => {
    const { POST } = await import("./route");
    const subject = createHash("sha256").update("s".repeat(43)).digest("base64url");
    const response = await POST(new Request("https://app.test/api/domains/challenge", { method: "POST", body: JSON.stringify({ url: "example.com/contact", subject }) }));
    expect(response.status).toBe(201);
    await expect(response.json()).resolves.toMatchObject({ hostname: "example.com", verificationUrl: "https://example.com/.well-known/africheck-verification.txt" });
    expect(resolvePublicUrl).toHaveBeenCalledWith(new URL("https://example.com/.well-known/africheck-verification.txt"));
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("échoue explicitement lorsque la fonctionnalité n’est pas configurée", async () => {
    delete process.env.DOMAIN_VERIFICATION_KEY;
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/challenge", { method: "POST", body: JSON.stringify({ url: "example.com", subject: "a".repeat(43) }) }));
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({ code: "VERIFICATION_DISABLED", requestId: "req-domain" });
    expect(resolvePublicUrl).not.toHaveBeenCalled();
  });

  it("limite le corps avant de le parser", async () => {
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/domains/challenge", { method: "POST", headers: { "content-length": "5000" }, body: "{}" }));
    expect(response.status).toBe(413);
  });
});
