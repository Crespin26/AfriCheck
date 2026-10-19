import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/transport", () => ({
  fetchWebsite: vi.fn(async (url: URL) => ({
    status: 200, headers: new Headers({ "content-type": "text/html" }),
    cookies: [], body: "<html><body>Test</body></html>", finalUrl: url,
    tls: { authorized: true, validTo: "2035-01-01T00:00:00.000Z", protocol: "TLSv1.3" },
  })),
}));

describe("parcours API diagnostic vers PDF", () => {
  it("exporte le diagnostic du scanner et refuse sa modification", async () => {
    const { POST: scan } = await import("@/app/api/scan/route");
    const { POST: report } = await import("@/app/api/report/route");
    const scanResponse = await scan(new Request("https://app.test/api/scan", {
      method: "POST", body: JSON.stringify({ url: "example.com" }),
    }));
    expect(scanResponse.status).toBe(200);
    const result = await scanResponse.json();
    const exportResponse = await report(new Request("https://app.test/api/report", {
      method: "POST", body: JSON.stringify(result),
    }));
    expect(exportResponse.status).toBe(200);
    expect(Buffer.from(await exportResponse.arrayBuffer()).subarray(0, 5).toString()).toBe("%PDF-");
    const tampered = await report(new Request("https://app.test/api/report", {
      method: "POST", body: JSON.stringify({ ...result, score: result.score === 100 ? 99 : 100 }),
    }));
    expect(tampered.status).toBe(403);
    await expect(tampered.json()).resolves.toMatchObject({ code: "REPORT_UNAUTHORIZED" });
  });
});
