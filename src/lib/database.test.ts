import { afterEach, describe, expect, it } from "vitest";
import { databaseConfiguration, DatabaseConfigurationError, historyRetentionDays } from "./database";

const originalRetention = process.env.HISTORY_RETENTION_DAYS;

afterEach(() => {
  delete globalThis.africheckDatabasePool;
  if (originalRetention === undefined) delete process.env.HISTORY_RETENTION_DAYS;
  else process.env.HISTORY_RETENTION_DAYS = originalRetention;
});

describe("configuration PostgreSQL", () => {
  it("désactive explicitement l’historique sans URL", () => expect(() => databaseConfiguration({})).toThrow(expect.objectContaining({ code: "DATABASE_DISABLED" })));
  it("accepte une URL PostgreSQL et TLS explicite", () => expect(databaseConfiguration({ DATABASE_URL: "postgres://user:pass@db.example/africheck", DATABASE_SSL: "true" })).toEqual({ connectionString: "postgres://user:pass@db.example/africheck", ssl: true }));
  it("rejette les protocoles et valeurs TLS ambigus", () => {
    expect(() => databaseConfiguration({ DATABASE_URL: "https://db.example/africheck" })).toThrow(DatabaseConfigurationError);
    expect(() => databaseConfiguration({ DATABASE_URL: "postgres://db.example/africheck", DATABASE_SSL: "yes" })).toThrow(DatabaseConfigurationError);
  });
  it("borne la rétention entre 1 et 365 jours", () => {
    delete process.env.HISTORY_RETENTION_DAYS;
    expect(historyRetentionDays()).toBe(90);
    expect(historyRetentionDays("30")).toBe(30);
    expect(() => historyRetentionDays("0")).toThrow(DatabaseConfigurationError);
    expect(() => historyRetentionDays("366")).toThrow(DatabaseConfigurationError);
  });
});
