import { beforeEach, describe, expect, it, vi } from "vitest";
import { scanWebsite } from "@/lib/scanner";
import { ScanError } from "@/lib/errors";
import { logScanEvent } from "@/lib/observability";

const verifyOwnershipProof = vi.fn(() => ({ hostname: "example.com", subject: "subject" }));
const saveScanHistory = vi.fn(async () => "history-1");

vi.mock("@/lib/scanner", () => ({ scanWebsite: vi.fn(async (url: string) => ({ url, score: 80 })) }));
vi.mock("@/lib/observability", () => ({ createRequestId: () => "req-test", clientFingerprint: () => undefined, logScanEvent: vi.fn() }));
vi.mock("@/lib/domain-verification", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/lib/domain-verification")>()), verifyOwnershipProof }));
vi.mock("@/lib/scan-history", () => ({ saveScanHistory }));

beforeEach(() => { vi.resetModules(); vi.clearAllMocks(); delete process.env.TRUST_PROXY_HEADERS; delete process.env.DOMAIN_VERIFICATION_KEY; });

describe("POST /api/scan", () => {
  it("refuse un JSON invalide sans exposer l’erreur du parseur", async () => {
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/scan", { method: "POST", body: "{" }));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "Le corps de la requête doit être un JSON valide.", code: "INVALID_REQUEST", requestId: "req-test" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toBe("req-test");
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

  it("retourne un code stable et journalise un échec sans la cible", async () => {
    vi.mocked(scanWebsite).mockRejectedValueOnce(new ScanError("TARGET_BLOCKED", "Cette adresse réseau n’est pas autorisée."));
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/scan", { method: "POST", body: JSON.stringify({ url: "http://127.0.0.1" }) }));
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({ code: "TARGET_BLOCKED", requestId: "req-test" });
    expect(logScanEvent).toHaveBeenCalledWith(expect.objectContaining({ event: "scan.failed", errorCode: "TARGET_BLOCKED", requestId: "req-test" }));
    expect(JSON.stringify(vi.mocked(logScanEvent).mock.calls)).not.toContain("127.0.0.1");
  });

  it("enregistre le scan uniquement avec une preuve correspondant au domaine final", async () => {
    process.env.DOMAIN_VERIFICATION_KEY = "k".repeat(32);
    vi.mocked(scanWebsite).mockResolvedValueOnce({ url: "https://example.com/", finalUrl: "https://example.com/", scannedAt: "2026-08-27T12:00:00.000Z", durationMs: 100, score: 82, grade: "B", findings: [] });
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/scan", { method: "POST", body: JSON.stringify({ url: "example.com", ownership: { proof: "signed", clientSecret: "s".repeat(43) } }) }));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ history: { saved: true, id: "history-1" } });
    expect(verifyOwnershipProof).toHaveBeenCalled();
    expect(saveScanHistory).toHaveBeenCalledWith("example.com", expect.objectContaining({ score: 82 }));
  });

  it("n’enregistre pas un scan redirigé vers un autre domaine", async () => {
    process.env.DOMAIN_VERIFICATION_KEY = "k".repeat(32);
    vi.mocked(scanWebsite).mockResolvedValueOnce({ url: "https://example.com/", finalUrl: "https://other.example/", scannedAt: "2026-08-27T12:00:00.000Z", durationMs: 100, score: 82, grade: "B", findings: [] });
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/scan", { method: "POST", body: JSON.stringify({ url: "example.com", ownership: { proof: "signed", clientSecret: "s".repeat(43) } }) }));
    await expect(response.json()).resolves.toMatchObject({ history: { saved: false, code: "DOMAIN_MISMATCH" } });
    expect(saveScanHistory).not.toHaveBeenCalled();
  });
});
