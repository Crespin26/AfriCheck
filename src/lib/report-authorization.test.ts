import { afterEach, describe, expect, it, vi } from "vitest";
import { authorizeReport, reportSigningKey, verifyReportAuthorization } from "./report-authorization";
import type { ReportInput } from "./pdf-report";

afterEach(() => vi.unstubAllEnvs());

const key = Buffer.alloc(32, 1);
const now = Date.UTC(2026, 9, 19);
const input: ReportInput = {
  finalUrl: "https://example.com/", scannedAt: new Date(now).toISOString(),
  durationMs: 100, score: 80, grade: "B",
  findings: [{ id: "https", title: "HTTPS", status: "pass", points: 8, maxPoints: 10,
    observation: "Connexion chiffrée.", recommendation: "Conserver HTTPS." }],
};

describe("autorisation d’export PDF", () => {
  it("valide un résultat signé avec la même clé sur une autre instance", () => {
    const authorization = authorizeReport(input, key, now);
    expect(verifyReportAuthorization(input, authorization, Buffer.from(key), now + 1)).toBe(true);
  });

  it.each([
    { score: 100 }, { grade: "A" as const }, { finalUrl: "https://other.example/" },
    { scannedAt: new Date(now + 1).toISOString() }, { durationMs: 1 },
    { findings: [{ ...input.findings[0], observation: "Aucun problème." }] },
    { findings: [{ ...input.findings[0], points: 10 }] },
  ])("refuse un résultat modifié : %j", (change) => {
    expect(verifyReportAuthorization({ ...input, ...change }, authorizeReport(input, key, now), key, now)).toBe(false);
  });

  it("signe également la version de calcul pour empêcher son changement", () => {
    const current = { ...input, scoringVersion: 2 as const };
    const authorization = authorizeReport(current, key, now);
    expect(verifyReportAuthorization(current, authorization, key, now)).toBe(true);
    expect(verifyReportAuthorization(input, authorization, key, now)).toBe(false);
  });
  it("refuse les signatures absentes, mal formées, expirées ou signées avec une autre clé", () => {
    const authorization = authorizeReport(input, key, now);
    for (const invalid of [undefined, null, {}, { ...authorization, signature: "x" },
      { ...authorization, expiresAt: authorization.expiresAt + 1 }]) {
      expect(verifyReportAuthorization(input, invalid, key, now)).toBe(false);
    }
    expect(verifyReportAuthorization(input, authorization, key, authorization.expiresAt)).toBe(false);
    expect(verifyReportAuthorization(input, authorization, Buffer.alloc(32, 2), now)).toBe(false);
  });

  it("ignore l’ordre des propriétés et les métadonnées d’historique", () => {
    const reordered = { ...input, findings: input.findings.map((finding) => ({
      recommendation: finding.recommendation, observation: finding.observation,
      maxPoints: finding.maxPoints, points: finding.points, status: finding.status,
      title: finding.title, id: finding.id,
    })) };
    expect(verifyReportAuthorization(reordered, authorizeReport(input, key, now), key, now)).toBe(true);
  });

  it("refuse une clé configurée trop courte et réutilise la clé locale du processus", () => {
    expect(() => reportSigningKey("short")).toThrow("REPORT_SIGNING_KEY");
    expect(reportSigningKey("k".repeat(32))).toEqual(Buffer.from("k".repeat(32)));
    vi.stubEnv("REPORT_SIGNING_KEY", undefined);
    expect(reportSigningKey()).toBe(reportSigningKey());
  });
});
