import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateReportPdf } from "@/lib/pdf-report";

vi.mock("@/lib/observability", () => ({ createRequestId: () => "report-request" }));
vi.mock("@/lib/pdf-report", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/pdf-report")>();
  return { ...original, generateReportPdf: vi.fn(async () => new Uint8Array([37, 80, 68, 70])) };
});

const payload = { finalUrl: "https://example.com/private", scannedAt: "2026-08-27T12:00:00.000Z", durationMs: 1000, score: 80, grade: "B", findings: [{ id: "https", title: "HTTPS", status: "pass", points: 10, maxPoints: 10, observation: "Connexion chiffree.", recommendation: "Aucune action." }] };

beforeEach(() => { vi.resetModules(); vi.mocked(generateReportPdf).mockClear(); });

describe("POST /api/report", () => {
  it("retourne un PDF avec un nom de fichier neutralisé", async () => {
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/report", { method: "POST", body: JSON.stringify(payload) }));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/pdf");
    expect(response.headers.get("content-disposition")).toContain("africheck-example.com-2026-08-27.pdf");
    expect(response.headers.get("x-request-id")).toBe("report-request");
  });
  it("rejette les données invalides", async () => {
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/report", { method: "POST", body: JSON.stringify({ ...payload, score: 999 }) }));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ code: "INVALID_REPORT" });
  });
  it("distingue une panne interne de génération", async () => {
    vi.mocked(generateReportPdf).mockRejectedValueOnce(new Error("internal path"));
    const { POST } = await import("./route");
    const response = await POST(new Request("https://app.test/api/report", { method: "POST", body: JSON.stringify(payload) }));
    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({ error: "Le rapport ne peut pas être généré pour le moment.", code: "REPORT_GENERATION_FAILED", requestId: "report-request" });
  });
});
