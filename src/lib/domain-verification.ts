import "server-only";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { normalizeUrl } from "./url-safety";
import { fetchWebsite, type ScanResponse } from "./transport";

const CHALLENGE_LIFETIME_MS = 15 * 60 * 1000;
const PROOF_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 60 * 1000;
const WELL_KNOWN_PATH = "/.well-known/africheck-verification.txt";
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;

export type DomainVerificationCode =
  | "VERIFICATION_DISABLED" | "INVALID_SUBJECT" | "INVALID_CLIENT_SECRET"
  | "INVALID_CHALLENGE" | "CHALLENGE_EXPIRED" | "SUBJECT_MISMATCH"
  | "VERIFICATION_FILE_MISSING" | "VERIFICATION_FILE_MISMATCH";

const publicMessages: Record<DomainVerificationCode, { message: string; status: number }> = {
  VERIFICATION_DISABLED: { message: "La vérification de domaine n’est pas configurée.", status: 503 },
  INVALID_SUBJECT: { message: "L’identifiant du navigateur est invalide.", status: 400 },
  INVALID_CLIENT_SECRET: { message: "Le secret du navigateur est invalide.", status: 400 },
  INVALID_CHALLENGE: { message: "Le challenge de vérification est invalide.", status: 400 },
  CHALLENGE_EXPIRED: { message: "Le challenge de vérification a expiré.", status: 410 },
  SUBJECT_MISMATCH: { message: "Ce challenge appartient à un autre navigateur.", status: 403 },
  VERIFICATION_FILE_MISSING: { message: "Le fichier de vérification est introuvable sur ce domaine.", status: 422 },
  VERIFICATION_FILE_MISMATCH: { message: "Le contenu du fichier de vérification ne correspond pas au challenge.", status: 422 },
};

export class DomainVerificationError extends Error {
  readonly status: number;
  constructor(public readonly code: DomainVerificationCode) {
    super(publicMessages[code].message);
    this.name = "DomainVerificationError";
    this.status = publicMessages[code].status;
  }
}

type TokenKind = "challenge" | "ownership";
type SignedPayload = {
  v: 1;
  kind: TokenKind;
  origin: string;
  host: string;
  subject: string;
  nonce: string;
  iat: number;
  exp: number;
};

export type DomainChallenge = { challenge: string; verificationUrl: string; hostname: string; expiresAt: string };
export type OwnershipProof = { proof: string; hostname: string; expiresAt: string };
export type WebsiteFetcher = (url: URL, options: { maxBodyBytes: number; timeoutMs: number; maxRedirects: number }) => Promise<ScanResponse>;

export function domainVerificationKey(value = process.env.DOMAIN_VERIFICATION_KEY): Buffer {
  if (!value || Buffer.byteLength(value, "utf8") < 32) throw new DomainVerificationError("VERIFICATION_DISABLED");
  return Buffer.from(value, "utf8");
}

export function hashClientSecret(clientSecret: string): string {
  if (!BASE64URL_32_BYTES.test(clientSecret)) throw new DomainVerificationError("INVALID_CLIENT_SECRET");
  return createHash("sha256").update(clientSecret, "utf8").digest("base64url");
}

function validateSubject(subject: string): void {
  if (!BASE64URL_32_BYTES.test(subject)) throw new DomainVerificationError("INVALID_SUBJECT");
}

function signPayload(payload: SignedPayload, key: Buffer): string {
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", key).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function parseToken(token: string, expectedKind: TokenKind, key: Buffer, now: number): SignedPayload {
  if (token.length > 2048) throw new DomainVerificationError("INVALID_CHALLENGE");
  const [encoded, signature, extra] = token.split(".");
  if (!encoded || !signature || extra || !safeEqual(createHmac("sha256", key).update(encoded).digest("base64url"), signature)) {
    throw new DomainVerificationError("INVALID_CHALLENGE");
  }
  let payload: Partial<SignedPayload>;
  try { payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Partial<SignedPayload>; }
  catch { throw new DomainVerificationError("INVALID_CHALLENGE"); }
  const valid = payload.v === 1 && payload.kind === expectedKind && typeof payload.origin === "string" && typeof payload.host === "string" &&
    typeof payload.subject === "string" && BASE64URL_32_BYTES.test(payload.subject) && typeof payload.nonce === "string" && BASE64URL_32_BYTES.test(payload.nonce) &&
    typeof payload.iat === "number" && Number.isSafeInteger(payload.iat) && typeof payload.exp === "number" && Number.isSafeInteger(payload.exp);
  if (!valid) throw new DomainVerificationError("INVALID_CHALLENGE");
  const typed = payload as SignedPayload;
  const maximumLifetime = expectedKind === "challenge" ? CHALLENGE_LIFETIME_MS : PROOF_LIFETIME_MS;
  if (typed.iat > now + MAX_CLOCK_SKEW_MS || typed.exp - typed.iat !== maximumLifetime) throw new DomainVerificationError("INVALID_CHALLENGE");
  if (typed.exp <= now) throw new DomainVerificationError("CHALLENGE_EXPIRED");
  let origin: URL;
  try { origin = new URL(typed.origin); } catch { throw new DomainVerificationError("INVALID_CHALLENGE"); }
  if (origin.origin !== typed.origin || origin.hostname !== typed.host || origin.pathname !== "/" || !["http:", "https:"].includes(origin.protocol)) {
    throw new DomainVerificationError("INVALID_CHALLENGE");
  }
  return typed;
}

export function createDomainChallenge(input: string, subject: string, key: Buffer, now = Date.now(), nonce = randomBytes(32).toString("base64url")): DomainChallenge {
  validateSubject(subject);
  if (!BASE64URL_32_BYTES.test(nonce)) throw new DomainVerificationError("INVALID_CHALLENGE");
  const url = normalizeUrl(input);
  const origin = url.origin;
  const payload: SignedPayload = { v: 1, kind: "challenge", origin, host: url.hostname, subject, nonce, iat: now, exp: now + CHALLENGE_LIFETIME_MS };
  return { challenge: signPayload(payload, key), verificationUrl: new URL(WELL_KNOWN_PATH, origin).href, hostname: url.hostname, expiresAt: new Date(payload.exp).toISOString() };
}

export async function verifyDomainChallenge(input: { challenge: string; clientSecret: string }, key: Buffer, now = Date.now(), fetcher: WebsiteFetcher = fetchWebsite): Promise<OwnershipProof> {
  const payload = parseToken(input.challenge, "challenge", key, now);
  const subject = hashClientSecret(input.clientSecret);
  if (!safeEqual(subject, payload.subject)) throw new DomainVerificationError("SUBJECT_MISMATCH");
  const response = await fetcher(new URL(WELL_KNOWN_PATH, payload.origin), { maxBodyBytes: 4096, timeoutMs: 8000, maxRedirects: 2 });
  if (response.status !== 200) throw new DomainVerificationError("VERIFICATION_FILE_MISSING");
  if (!safeEqual(response.body.trim(), input.challenge)) throw new DomainVerificationError("VERIFICATION_FILE_MISMATCH");
  const proofPayload: SignedPayload = { ...payload, kind: "ownership", nonce: randomBytes(32).toString("base64url"), iat: now, exp: now + PROOF_LIFETIME_MS };
  return { proof: signPayload(proofPayload, key), hostname: payload.host, expiresAt: new Date(proofPayload.exp).toISOString() };
}

export function verifyOwnershipProof(proof: string, clientSecret: string, key: Buffer, now = Date.now()): { hostname: string; subject: string } {
  const payload = parseToken(proof, "ownership", key, now);
  if (!safeEqual(hashClientSecret(clientSecret), payload.subject)) throw new DomainVerificationError("SUBJECT_MISMATCH");
  return { hostname: payload.host, subject: payload.subject };
}

export function toDomainVerificationError(error: unknown): { code: DomainVerificationCode; message: string; status: number } | undefined {
  if (!(error instanceof DomainVerificationError)) return undefined;
  return { code: error.code, message: publicMessages[error.code].message, status: publicMessages[error.code].status };
}
