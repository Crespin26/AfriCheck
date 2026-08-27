import { describe, expect, it, vi } from "vitest";
import { listScanHistory, saveScanHistory, type HistoryQuery } from "./scan-history";
import type { ScanResult } from "./types";

const result: ScanResult = { url: "https://example.com/", finalUrl: "https://example.com/", scannedAt: "2026-08-27T12:00:00.000Z", durationMs: 200, score: 82, grade: "B", findings: [] };

describe("historique des scans", () => {
  it("enregistre un rapport avec une rétention paramétrée et des requêtes paramétrées", async () => {
    process.env.HISTORY_RETENTION_DAYS = "30";
    const query = vi.fn(async () => ({ rows: [] })) as unknown as HistoryQuery;
    const id = await saveScanHistory("example.com", result, query);
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(query).toHaveBeenCalledTimes(2);
    expect(vi.mocked(query).mock.calls[1][0]).toContain("$7::jsonb");
    expect(vi.mocked(query).mock.calls[1][1]).toEqual([id, "example.com", result.scannedAt, 30, 82, "B", JSON.stringify(result)]);
    delete process.env.HISTORY_RETENTION_DAYS;
  });

  it("refuse d’enregistrer un résultat redirigé vers un autre domaine", async () => {
    const query = vi.fn(async () => ({ rows: [] })) as unknown as HistoryQuery;
    await expect(saveScanHistory("example.com", { ...result, finalUrl: "https://other.example/" }, query)).rejects.toThrow("ne correspond pas");
    expect(query).not.toHaveBeenCalled();
  });

  it("retourne uniquement les résumés et borne la limite", async () => {
    const query = vi.fn(async () => ({ rows: [{ id: "scan-1", scanned_at: new Date("2026-08-27T12:00:00Z"), score: 82, grade: "B" }] })) as unknown as HistoryQuery;
    await expect(listScanHistory("example.com", 500, query)).resolves.toEqual([{ id: "scan-1", scannedAt: "2026-08-27T12:00:00.000Z", score: 82, grade: "B" }]);
    expect(vi.mocked(query).mock.calls[0][1]).toEqual(["example.com", 50]);
  });
});
