export const CLIENT_SECRET_STORAGE_KEY = "africheck.domain-client-secret.v1";
export const OWNERSHIP_PROOFS_STORAGE_KEY = "africheck.domain-proofs.v1";

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

export async function createBrowserIdentity(storage: Storage, cryptoApi: Crypto): Promise<BrowserIdentity> {
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
  return { secret, subject: bytesToBase64Url(new Uint8Array(digest)), persistent };
}

export function saveOwnershipProof(storage: Storage, value: StoredOwnershipProof): boolean {
  if (!value.hostname || !value.proof || !Number.isFinite(Date.parse(value.expiresAt))) return false;
  try {
    let current: Record<string, StoredOwnershipProof> = Object.create(null) as Record<string, StoredOwnershipProof>;
    const raw = storage.getItem(OWNERSHIP_PROOFS_STORAGE_KEY);
    if (raw) {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) current = Object.assign(Object.create(null) as Record<string, StoredOwnershipProof>, parsed);
    }
    current[value.hostname] = value;
    storage.setItem(OWNERSHIP_PROOFS_STORAGE_KEY, JSON.stringify(current));
    return true;
  } catch { return false; }
}

export function readOwnershipProof(storage: Storage, hostname: string, now = Date.now()): StoredOwnershipProof | undefined {
  try {
    const raw = storage.getItem(OWNERSHIP_PROOFS_STORAGE_KEY);
    if (!raw) return undefined;
    const parsed = JSON.parse(raw) as Record<string, Partial<StoredOwnershipProof>>;
    const candidate = parsed?.[hostname];
    if (candidate?.hostname !== hostname || typeof candidate.proof !== "string" || typeof candidate.expiresAt !== "string" || Date.parse(candidate.expiresAt) <= now) return undefined;
    return candidate as StoredOwnershipProof;
  } catch { return undefined; }
}
