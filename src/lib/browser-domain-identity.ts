export const CLIENT_SECRET_STORAGE_KEY = "africheck.domain-client-secret.v1";
export const OWNERSHIP_PROOFS_STORAGE_KEY = "africheck.domain-proofs.v1";

type BrowserStorage = Pick<Storage, "getItem" | "setItem">;
const unavailableStorage: BrowserStorage = {
  getItem() { throw new Error("Stockage local indisponible."); },
  setItem() { throw new Error("Stockage local indisponible."); },
};
const temporaryIdentities = new WeakMap<BrowserStorage, BrowserIdentity>();
const temporaryProofs = new WeakMap<BrowserStorage, Map<string, StoredOwnershipProof>>();

export function browserStorage(): BrowserStorage {
  try { return window.localStorage; }
  catch { return unavailableStorage; }
}

export type BrowserIdentity = { secret: string; subject: string; persistent: boolean };
export type StoredOwnershipProof = { proof: string; hostname: string; expiresAt: string };

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function validSecret(value: string | null): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export async function createBrowserIdentity(storage: BrowserStorage, cryptoApi: Crypto): Promise<BrowserIdentity> {
  if (!cryptoApi?.subtle) throw new Error("La vérification de domaine nécessite une connexion HTTPS à AfriCheck.");
  const temporary = temporaryIdentities.get(storage);
  if (temporary) return temporary;
  let secret: string | null = null;
  let persistent = true;
  try { secret = storage.getItem(CLIENT_SECRET_STORAGE_KEY); }
  catch { persistent = false; }
  if (!validSecret(secret)) {
    secret = bytesToBase64Url(cryptoApi.getRandomValues(new Uint8Array(32)));
    try { storage.setItem(CLIENT_SECRET_STORAGE_KEY, secret); }
    catch { persistent = false; }
  }
  const digest = await cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  const identity = { secret, subject: bytesToBase64Url(new Uint8Array(digest)), persistent };
  if (!persistent) temporaryIdentities.set(storage, identity);
  return identity;
}

export function saveOwnershipProof(storage: BrowserStorage, value: StoredOwnershipProof): boolean {
  if (!value.hostname || !value.proof || !Number.isFinite(Date.parse(value.expiresAt))) return false;
  try {
    let current: Record<string, StoredOwnershipProof> = Object.create(null) as Record<string, StoredOwnershipProof>;
    const raw = storage.getItem(OWNERSHIP_PROOFS_STORAGE_KEY);
    if (raw) {
      let parsed: unknown;
      try { parsed = JSON.parse(raw); } catch { parsed = undefined; }
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) current = Object.assign(Object.create(null) as Record<string, StoredOwnershipProof>, parsed);
    }
    current[value.hostname] = value;
    storage.setItem(OWNERSHIP_PROOFS_STORAGE_KEY, JSON.stringify(current));
    temporaryProofs.get(storage)?.delete(value.hostname);
    return true;
  } catch {
    let proofs = temporaryProofs.get(storage);
    if (!proofs) { proofs = new Map(); temporaryProofs.set(storage, proofs); }
    proofs.set(value.hostname, value);
    return false;
  }
}

export function readOwnershipProof(storage: BrowserStorage, hostname: string, now = Date.now()): StoredOwnershipProof | undefined {
  const temporary = temporaryProofs.get(storage)?.get(hostname);
  if (temporary && Date.parse(temporary.expiresAt) > now) return temporary;
  try {
    const raw = storage.getItem(OWNERSHIP_PROOFS_STORAGE_KEY);
    if (!raw) return undefined;
    const parsed = JSON.parse(raw) as Record<string, Partial<StoredOwnershipProof>>;
    const candidate = parsed?.[hostname];
    if (candidate?.hostname !== hostname || typeof candidate.proof !== "string" || typeof candidate.expiresAt !== "string" || !Number.isFinite(Date.parse(candidate.expiresAt)) || Date.parse(candidate.expiresAt) <= now) return undefined;
    return candidate as StoredOwnershipProof;
  } catch { return undefined; }
}
