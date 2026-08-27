import { afterEach, describe, expect, it, vi } from "vitest";
import { clientFingerprint, createRequestId, logScanEvent } from "./observability";

afterEach(() => { delete process.env.LOG_HASH_KEY; vi.restoreAllMocks(); });

describe("observability", () => {
  it("génère des identifiants de corrélation distincts", () => expect(createRequestId()).not.toBe(createRequestId()));
  it("ne dérive aucun identifiant sans clé suffisamment forte", () => {
    expect(clientFingerprint("1.2.3.4")).toBeUndefined();
    process.env.LOG_HASH_KEY = "short"; expect(clientFingerprint("1.2.3.4")).toBeUndefined();
  });
  it("produit un pseudonyme stable avec une clé de 32 caractères", () => {
    process.env.LOG_HASH_KEY = "a".repeat(32);
    expect(clientFingerprint("1.2.3.4")).toBe(clientFingerprint("1.2.3.4"));
    expect(clientFingerprint("1.2.3.4")).not.toBe(clientFingerprint("5.6.7.8"));
  });
  it("écrit un événement JSON structuré sans URL", () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    logScanEvent({ event: "scan.completed", requestId: "req-1", durationMs: 120, score: 82, grade: "B" });
    const record = JSON.parse(info.mock.calls[0][0] as string);
    expect(record).toMatchObject({ service: "africheck", event: "scan.completed", requestId: "req-1", score: 82 });
    expect(record).not.toHaveProperty("url");
  });
});
