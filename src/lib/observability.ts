import { createHmac, randomUUID } from "node:crypto";
import type { ErrorCode } from "./errors";

type ScanEvent = {
  event: "scan.completed" | "scan.failed" | "scan.rate_limited" | "scan.rejected" | "scan.busy";
  requestId: string;
  durationMs: number;
  errorCode?: ErrorCode | "RATE_LIMITED" | "INVALID_REQUEST" | "SCAN_BUSY";
  score?: number;
  grade?: string;
  historySaved?: boolean;
  historyError?: "HISTORY_DISABLED" | "HISTORY_UNAVAILABLE" | "DOMAIN_MISMATCH";
  clientFingerprint?: string;
};

export function createRequestId(): string { return randomUUID(); }

export function clientFingerprint(identity: string): string | undefined {
  const key = process.env.LOG_HASH_KEY;
  if (!key || key.length < 32 || identity === "shared" || identity === "unknown") return undefined;
  return createHmac("sha256", key).update(identity).digest("hex").slice(0, 16);
}

export function logScanEvent(event: ScanEvent): void {
  const record = JSON.stringify({ timestamp: new Date().toISOString(), service: "africheck", ...event });
  if (event.event === "scan.failed") console.error(record);
  else if (event.event === "scan.rate_limited" || event.event === "scan.rejected" || event.event === "scan.busy") console.warn(record);
  else console.info(record);
}
