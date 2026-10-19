import "server-only";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { ReportInput } from "./pdf-report";
import type { ReportAuthorization } from "./types";

const LIFETIME_MS = 60 * 60 * 1000;

declare global {
  var africheckReportKey: Buffer | undefined;
}

export function reportSigningKey(value = process.env.REPORT_SIGNING_KEY): Buffer {
  if (value !== undefined) {
    if (Buffer.byteLength(value, "utf8") < 32) throw new Error("REPORT_SIGNING_KEY doit contenir au moins 32 octets.");
    return Buffer.from(value, "utf8");
  }
  // Shared by route bundles and development reloads within this process only.
  return globalThis.africheckReportKey ??= randomBytes(32);
}

function signature(input: ReportInput, expiresAt: number, key: Buffer): Buffer {
  const report: ReportInput = {
    finalUrl: new URL(input.finalUrl).href,
    scannedAt: input.scannedAt,
    durationMs: input.durationMs,
    score: input.score,
    grade: input.grade,
    findings: input.findings.map((finding) => ({
      id: finding.id, title: finding.title, status: finding.status,
      points: finding.points, maxPoints: finding.maxPoints,
      observation: finding.observation, recommendation: finding.recommendation,
    })),
  };
  return createHmac("sha256", key).update(JSON.stringify(["africheck-report-v1", expiresAt, report])).digest();
}

export function authorizeReport(input: ReportInput, key = reportSigningKey(), now = Date.now()): ReportAuthorization {
  const expiresAt = now + LIFETIME_MS;
  return { expiresAt, signature: signature(input, expiresAt, key).toString("base64url") };
}

export function verifyReportAuthorization(input: ReportInput, authorization: unknown, key = reportSigningKey(), now = Date.now()): boolean {
  if (!authorization || typeof authorization !== "object") return false;
  const candidate = authorization as Partial<ReportAuthorization>;
  if (typeof candidate.expiresAt !== "number" || !Number.isSafeInteger(candidate.expiresAt)
    || candidate.expiresAt <= now || candidate.expiresAt > now + LIFETIME_MS
    || typeof candidate.signature !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(candidate.signature)) return false;
  const expected = signature(input, candidate.expiresAt, key);
  const supplied = Buffer.from(candidate.signature, "base64url");
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}
