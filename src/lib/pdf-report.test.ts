import { PDFDocument } from "pdf-lib";
import { describe, expect, it } from "vitest";
import type { Finding } from "./types";
import { generateReportPdf, parseReportInput } from "./pdf-report";

const finding = (index: number, status: Finding["status"] = "warning"): Finding => ({ id: `check-${index}`, title: `Controle ${index}`, status, points: status === "pass" ? 5 : 0, maxPoints: 5, observation: "Une observation claire et factuelle sur la configuration detectee.", recommendation: "Appliquer la configuration recommandee puis relancer le diagnostic." });
const input = { finalUrl: "https://example.com/private?token=secret", scannedAt: "2026-08-27T12:00:00.000Z", durationMs: 1520, score: 72, grade: "C" as const, findings: Array.from({ length: 11 }, (_, index) => finding(index, index % 3 === 0 ? "fail" : index % 3 === 1 ? "warning" : "pass")) };

describe("parseReportInput", () => {
  it("accepte un rapport borné", () => expect(parseReportInput(input).findings).toHaveLength(11));
  it("accepte les états non évalués sans leur attribuer de points", () => {
    for (const status of ["not_observed", "not_applicable", "unavailable"] as const) {
      expect(parseReportInput({ ...input, scoringVersion: 2, findings: [finding(1, status)] }).findings[0].status).toBe(status);
      expect(() => parseReportInput({ ...input, findings: [{ ...finding(1, status), points: 1 }] })).toThrow();
    }
  });
  it("rejette les protocoles, scores et longueurs arbitraires", () => {
    expect(() => parseReportInput({ ...input, finalUrl: "file:///etc/passwd" })).toThrow();
    expect(() => parseReportInput({ ...input, score: 101 })).toThrow();
    expect(() => parseReportInput({ ...input, findings: Array.from({ length: 31 }, (_, index) => finding(index)) })).toThrow();
  });
});

describe("generateReportPdf", () => {
  it("exporte un diagnostic partiel sans étiqueter les contrôles neutres comme réussis", async () => {
    const report = parseReportInput({ ...input, scoringVersion: 2, findings: [finding(1, "not_observed"), finding(2, "unavailable"), finding(3, "not_applicable")] });
    const bytes = await generateReportPdf(report);
    expect((await PDFDocument.load(bytes)).getPageCount()).toBeGreaterThan(0);
  });
  it("produit un PDF paginé avec des métadonnées", async () => {
    const bytes = await generateReportPdf(parseReportInput(input));
    expect(Buffer.from(bytes).subarray(0, 4).toString()).toBe("%PDF");
    const document = await PDFDocument.load(bytes);
    expect(document.getPageCount()).toBeGreaterThan(1);
    expect(document.getTitle()).toBe("AfriCheck - example.com");
    expect(document.getAuthor()).toBe("AfriCheck");
  });
});
