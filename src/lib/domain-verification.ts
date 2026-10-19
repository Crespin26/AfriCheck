import "server-only";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { normalizeUrl } from "./url-safety";
import { fetchWebsite, type ScanResponse, type TransportOptions } from "./transport";

const CHALLENGE_LIFETIME_MS = 15 * 60 * 1000;
const PROOF_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 60 * 1000;
const WELL_KNOWN_PATH = "/.well-known/africheck-verification.txt";
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;

export type DomainVerificationCode =
  | "VERIFICATION_DISABLED" | "INVALID_SUBJECT" | "INVALID_CLIENT_SECRET"
  | "INVALID_CHALLENGE" | "CHALLENGE_EXPIRED" | "PROOF_EXPIRED" | "SUBJECT_MISMATCH"
  | "DOMAIN_MISMATCH" | "VERIFICATION_HTTPS_REQUIRED" | "VERIFICATION_FILE_MISSING" | "VERIFICATION_FILE_MISMATCH";

const publicMessages: Record<DomainVerificationCode, { message: string; status: number }> = {
  VERIFICATION_DISABLED: { message: "La vérification de domaine n’est pas configurée.", status: 503 },
  INVALID_SUBJECT: { message: "L’identifiant du navigateur est invalide.", status: 400 },
  INVALID_CLIENT_SECRET: { message: "Le secret du navigateur est invalide.", status: 400 },
  INVALID_CHALLENGE: { message: "Le challenge de vérification est invalide.", status: 400 },
  CHALLENGE_EXPIRED: { message: "Le challenge de vérification a expiré.", status: 410 },
  PROOF_EXPIRED: { message: "La preuve de contrôle du domaine a expiré.", status: 410 },
  SUBJECT_MISMATCH: { message: "Ce challenge appartient à un autre navigateur.", status: 403 },
  DOMAIN_MISMATCH: { message: "La preuve ne correspond pas au domaine demandé.", status: 403 },
  VERIFICATION_HTTPS_REQUIRED: { message: "La vérification exige HTTPS et un certificat TLS valide.", status: 422 },
  VERIFICATION_FILE_MISSING: { message: "Le fichier de vérification est introuvable sur ce domaine.", status: 422 },
  VERIFICATION_FILE_MISMATCH: { message: "Le contenu du fichier de vérification ne correspond pas au challenge.", status: 422 },
};

/**
 * Associe une erreur de preuve de domaine à un code stable, un message public et un statut HTTP.
 */
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
export type WebsiteFetcher = (url: URL, options: TransportOptions) => Promise<ScanResponse>;

/**
 * Charge une clé de signature d’au moins 32 octets ; désactive la vérification si elle est absente ou trop courte.
 */
export function domainVerificationKey(value = process.env.DOMAIN_VERIFICATION_KEY): Buffer {
  if (!value || Buffer.byteLength(value, "utf8") < 32) throw new DomainVerificationError("VERIFICATION_DISABLED");
  return Buffer.from(value, "utf8");
}

/**
 * Valide le format du secret du navigateur et calcule l’empreinte à laquelle les jetons sont liés.
 */
export function hashClientSecret(clientSecret: string): string {
  if (!BASE64URL_32_BYTES.test(clientSecret)) throw new DomainVerificationError("INVALID_CLIENT_SECRET");
  return createHash("sha256").update(clientSecret, "utf8").digest("base64url");
}

/**
 * Refuse un identifiant navigateur qui ne respecte pas le format base64url attendu.
 */
function validateSubject(subject: string): void {
  if (!BASE64URL_32_BYTES.test(subject)) throw new DomainVerificationError("INVALID_SUBJECT");
}

/**
 * Signe la charge utile avec HMAC-SHA-256 ; le jeton est authentifié, mais son contenu n’est pas chiffré.
 */
function signPayload(payload: SignedPayload, key: Buffer): string {
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", key).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

/**
 * Compare deux chaînes de même taille en temps constant pour vérifier les signatures et les secrets dérivés.
 */
function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Vérifie la signature, le type, la structure, les dates et la cohérence du domaine avant d’accepter un jeton.
 */
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
  if (typed.exp <= now) throw new DomainVerificationError(expectedKind === "challenge" ? "CHALLENGE_EXPIRED" : "PROOF_EXPIRED");
  let origin: URL;
  try { origin = new URL(typed.origin); } catch { throw new DomainVerificationError("INVALID_CHALLENGE"); }
  if (origin.origin !== typed.origin || origin.hostname !== typed.host || origin.pathname !== "/" || !["http:", "https:"].includes(origin.protocol)) {
    throw new DomainVerificationError("INVALID_CHALLENGE");
  }
  return typed;
}

/**
 * Émet un challenge signé valable 15 minutes, lié au navigateur et au domaine.
 * Le fichier demandé est toujours publié en HTTPS à un chemin fixe.
 */
export function createDomainChallenge(input: string, subject: string, key: Buffer, now = Date.now(), nonce = randomBytes(32).toString("base64url")): DomainChallenge {
  validateSubject(subject);
  if (!BASE64URL_32_BYTES.test(nonce)) throw new DomainVerificationError("INVALID_CHALLENGE");
  const url = normalizeUrl(input);
  url.protocol = "https:";
  const origin = url.origin;
  const payload: SignedPayload = { v: 1, kind: "challenge", origin, host: url.hostname, subject, nonce, iat: now, exp: now + CHALLENGE_LIFETIME_MS };
  return { challenge: signPayload(payload, key), verificationUrl: new URL(WELL_KNOWN_PATH, origin).href, hostname: url.hostname, expiresAt: new Date(payload.exp).toISOString() };
}

/**
 * Lit le fichier de challenge en HTTPS avec certificat valide, sans suivre de redirection.
 * Émet une preuve de 30 jours uniquement si le fichier et le secret du navigateur correspondent.
 */
export async function verifyDomainChallenge(input: { challenge: string; clientSecret: string }, key: Buffer, now = Date.now(), fetcher: WebsiteFetcher = fetchWebsite): Promise<OwnershipProof> {
  const payload = parseToken(input.challenge, "challenge", key, now);
  const subject = hashClientSecret(input.clientSecret);
  if (!safeEqual(subject, payload.subject)) throw new DomainVerificationError("SUBJECT_MISMATCH");
  const verificationUrl = new URL(WELL_KNOWN_PATH, payload.origin);
  if (verificationUrl.protocol !== "https:") throw new DomainVerificationError("VERIFICATION_HTTPS_REQUIRED");
  const response = await fetcher(verificationUrl, { maxBodyBytes: 4096, timeoutMs: 8000, maxRedirects: 0, requireValidTls: true });
  if (response.finalUrl.href !== verificationUrl.href) throw new DomainVerificationError("DOMAIN_MISMATCH");
  if (!response.tls?.authorized) throw new DomainVerificationError("VERIFICATION_HTTPS_REQUIRED");
  if (response.status !== 200) throw new DomainVerificationError("VERIFICATION_FILE_MISSING");
  if (!safeEqual(response.body.trim(), input.challenge)) throw new DomainVerificationError("VERIFICATION_FILE_MISMATCH");
  const proofPayload: SignedPayload = { ...payload, kind: "ownership", nonce: randomBytes(32).toString("base64url"), iat: now, exp: now + PROOF_LIFETIME_MS };
  return { proof: signPayload(proofPayload, key), hostname: payload.host, expiresAt: new Date(proofPayload.exp).toISOString() };
}

/**
 * Valide la preuve signée et son lien avec le secret du navigateur, sans refaire de requête au domaine.
 */
export function verifyOwnershipProof(proof: string, clientSecret: string, key: Buffer, now = Date.now()): { hostname: string; subject: string } {
  const payload = parseToken(proof, "ownership", key, now);
  if (!safeEqual(hashClientSecret(clientSecret), payload.subject)) throw new DomainVerificationError("SUBJECT_MISMATCH");
  return { hostname: payload.host, subject: payload.subject };
}

/**
 * Traduit uniquement les erreurs de vérification reconnues en code, message public et statut HTTP.
 */
export function toDomainVerificationError(error: unknown): { code: DomainVerificationCode; message: string; status: number } | undefined {
  if (!(error instanceof DomainVerificationError)) return undefined;
  return { code: error.code, message: publicMessages[error.code].message, status: publicMessages[error.code].status };
}
