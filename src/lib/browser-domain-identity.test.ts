import { createHash, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CLIENT_SECRET_STORAGE_KEY, browserStorage, createBrowserIdentity, OWNERSHIP_PROOFS_STORAGE_KEY, readOwnershipProof, saveOwnershipProof } from "./browser-domain-identity";

afterEach(() => vi.unstubAllGlobals());

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

  it("explique la nécessité de HTTPS lorsque Web Crypto n’est pas disponible", async () => {
    await expect(createBrowserIdentity(new MemoryStorage(), {} as Crypto)).rejects.toThrow("connexion HTTPS");
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

  it("protège aussi un navigateur qui refuse l’accès à localStorage lui-même", async () => {
    vi.stubGlobal("window", Object.defineProperty({}, "localStorage", { get() { throw new Error("blocked"); } }));
    const storage = browserStorage();
    const first = await createBrowserIdentity(storage, webcrypto as Crypto);
    expect(first.persistent).toBe(false);
    expect(await createBrowserIdentity(browserStorage(), webcrypto as Crypto)).toEqual(first);
  });

  it("conserve temporairement le secret et la preuve si les écritures sont refusées", async () => {
    const storage = new MemoryStorage();
    storage.setItem = () => { throw new Error("quota"); };
    const identity = await createBrowserIdentity(storage, webcrypto as Crypto);
    expect(await createBrowserIdentity(storage, webcrypto as Crypto)).toEqual(identity);
    const proof = { hostname: "example.com", proof: "signed-proof", expiresAt: "2030-01-01T00:00:00.000Z" };
    expect(saveOwnershipProof(storage, proof)).toBe(false);
    expect(readOwnershipProof(storage, proof.hostname)).toEqual(proof);
    expect(readOwnershipProof(storage, proof.hostname, Date.UTC(2031, 0, 1))).toBeUndefined();
  });

  it("remplace un stockage de preuves corrompu et ignore une date invalide", () => {
    const storage = new MemoryStorage();
    storage.setItem(OWNERSHIP_PROOFS_STORAGE_KEY, JSON.stringify({ "example.com": { hostname: "example.com", proof: "invalid", expiresAt: "invalid" } }));
    expect(readOwnershipProof(storage, "example.com")).toBeUndefined();
    storage.setItem(OWNERSHIP_PROOFS_STORAGE_KEY, "{invalid");
    const proof = { hostname: "example.com", proof: "signed-proof", expiresAt: "2030-01-01T00:00:00.000Z" };
    expect(saveOwnershipProof(storage, proof)).toBe(true);
    expect(readOwnershipProof(storage, proof.hostname)).toEqual(proof);
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
