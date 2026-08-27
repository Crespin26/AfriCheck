import { createHash, webcrypto } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CLIENT_SECRET_STORAGE_KEY, createBrowserIdentity, OWNERSHIP_PROOFS_STORAGE_KEY, readOwnershipProof, saveOwnershipProof } from "./browser-domain-identity";

class MemoryStorage implements Storage {
  private values = new Map<string, string>();
  get length() { return this.values.size; }
  clear() { this.values.clear(); }
  getItem(key: string) { return this.values.get(key) ?? null; }
  key(index: number) { return [...this.values.keys()][index] ?? null; }
  removeItem(key: string) { this.values.delete(key); }
  setItem(key: string, value: string) { this.values.set(key, value); }
}

describe("identité locale de domaine", () => {
  it("génère une identité de 256 bits puis la réutilise", async () => {
    const storage = new MemoryStorage();
    const first = await createBrowserIdentity(storage, webcrypto as Crypto);
    const second = await createBrowserIdentity(storage, webcrypto as Crypto);
    expect(first.secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.subject).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.subject).toBe(createHash("sha256").update(first.secret).digest("base64url"));
    expect(second).toEqual(first);
    expect(storage.getItem(CLIENT_SECRET_STORAGE_KEY)).toBe(first.secret);
  });

  it("remplace une valeur locale mal formée", async () => {
    const storage = new MemoryStorage();
    storage.setItem(CLIENT_SECRET_STORAGE_KEY, "faible");
    const identity = await createBrowserIdentity(storage, webcrypto as Crypto);
    expect(identity.secret).not.toBe("faible");
  });

  it("continue en mode éphémère lorsque le stockage est indisponible", async () => {
    const storage = new MemoryStorage();
    storage.getItem = () => { throw new Error("blocked"); };
    storage.setItem = () => { throw new Error("blocked"); };
    const identity = await createBrowserIdentity(storage, webcrypto as Crypto);
    expect(identity.persistent).toBe(false);
    expect(identity.secret).toHaveLength(43);
  });

  it("stocke uniquement une preuve valide et ignore les preuves expirées", () => {
    const storage = new MemoryStorage();
    const proof = { hostname: "example.com", proof: "signed-proof", expiresAt: "2026-09-26T12:00:00.000Z" };
    expect(saveOwnershipProof(storage, proof)).toBe(true);
    expect(JSON.parse(storage.getItem(OWNERSHIP_PROOFS_STORAGE_KEY) ?? "{}")).toEqual({ "example.com": proof });
    expect(readOwnershipProof(storage, "example.com", Date.UTC(2026, 7, 27))).toEqual(proof);
    expect(readOwnershipProof(storage, "example.com", Date.UTC(2026, 9, 1))).toBeUndefined();
    expect(saveOwnershipProof(storage, { ...proof, expiresAt: "invalide" })).toBe(false);
  });
});
