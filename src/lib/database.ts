import "server-only";
import { Pool } from "pg";

declare global {
  var africheckDatabasePool: Pool | undefined;
}

export class DatabaseConfigurationError extends Error {
  constructor(public readonly code: "DATABASE_DISABLED" | "DATABASE_CONFIGURATION_INVALID") {
    super(code === "DATABASE_DISABLED" ? "L’historique n’est pas configuré." : "La configuration de l’historique est invalide.");
    this.name = "DatabaseConfigurationError";
  }
}

type DatabaseEnvironment = { DATABASE_URL?: string; DATABASE_SSL?: string };

export function databaseConfiguration(env?: DatabaseEnvironment): { connectionString: string; ssl: boolean } {
  const environment = env ?? { DATABASE_URL: process.env.DATABASE_URL, DATABASE_SSL: process.env.DATABASE_SSL };
  const connectionString = environment.DATABASE_URL;
  if (!connectionString) throw new DatabaseConfigurationError("DATABASE_DISABLED");
  if (environment.DATABASE_SSL !== undefined && environment.DATABASE_SSL !== "true" && environment.DATABASE_SSL !== "false") throw new DatabaseConfigurationError("DATABASE_CONFIGURATION_INVALID");
  try {
    const url = new URL(connectionString);
    if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname || !url.pathname.slice(1)) throw new Error("invalid");
  } catch { throw new DatabaseConfigurationError("DATABASE_CONFIGURATION_INVALID"); }
  return { connectionString, ssl: environment.DATABASE_SSL === "true" };
}

export function databasePool(): Pool {
  const configuration = databaseConfiguration();
  if (globalThis.africheckDatabasePool) return globalThis.africheckDatabasePool;
  const pool = new Pool({
    connectionString: configuration.connectionString,
    ssl: configuration.ssl ? { rejectUnauthorized: true } : undefined,
    max: 5,
    connectionTimeoutMillis: 3_000,
    idleTimeoutMillis: 30_000,
    maxUses: 5_000,
  });
  pool.on("error", () => console.error(JSON.stringify({ timestamp: new Date().toISOString(), service: "africheck", event: "database.pool_error" })));
  globalThis.africheckDatabasePool = pool;
  return pool;
}

export function historyRetentionDays(value = process.env.HISTORY_RETENTION_DAYS): number {
  if (value === undefined) return 90;
  const days = Number(value);
  if (!Number.isInteger(days) || days < 1 || days > 365) throw new DatabaseConfigurationError("DATABASE_CONFIGURATION_INVALID");
  return days;
}
