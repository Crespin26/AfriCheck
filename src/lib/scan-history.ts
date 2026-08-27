import "server-only";
import { randomUUID } from "node:crypto";
import type { QueryResultRow } from "pg";
import { databasePool, historyRetentionDays } from "./database";
import type { ScanResult } from "./types";

export type ScanHistorySummary = { id: string; scannedAt: string; score: number; grade: ScanResult["grade"] };
export type HistoryQuery = <T extends QueryResultRow>(text: string, values?: unknown[]) => Promise<{ rows: T[] }>;

type HistoryRow = QueryResultRow & { id: string; scanned_at: Date | string; score: number; grade: ScanResult["grade"] };

function defaultQuery<T extends QueryResultRow>(text: string, values?: unknown[]) {
  return databasePool().query<T>(text, values);
}

export async function saveScanHistory(hostname: string, result: ScanResult, query: HistoryQuery = defaultQuery): Promise<string> {
  const finalHostname = new URL(result.finalUrl).hostname;
  if (hostname !== finalHostname) throw new Error("Le domaine vérifié ne correspond pas au résultat du scan.");
  const id = randomUUID();
  const retentionDays = historyRetentionDays();
  await query("DELETE FROM scan_history WHERE expires_at <= now()");
  await query(
    "INSERT INTO scan_history (id, hostname, scanned_at, expires_at, score, grade, result) VALUES ($1, $2, $3, $3::timestamptz + ($4 * interval '1 day'), $5, $6, $7::jsonb)",
    [id, hostname, result.scannedAt, retentionDays, result.score, result.grade, JSON.stringify(result)],
  );
  return id;
}

export async function listScanHistory(hostname: string, limit = 20, query: HistoryQuery = defaultQuery): Promise<ScanHistorySummary[]> {
  const safeLimit = Math.min(50, Math.max(1, Math.trunc(limit)));
  const { rows } = await query<HistoryRow>(
    "SELECT id, scanned_at, score, grade FROM scan_history WHERE hostname = $1 AND expires_at > now() ORDER BY scanned_at DESC LIMIT $2",
    [hostname, safeLimit],
  );
  return rows.map((row) => ({ id: row.id, scannedAt: new Date(row.scanned_at).toISOString(), score: row.score, grade: row.grade }));
}
