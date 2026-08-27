import { describe, expect, it } from "vitest";
import { createDomainChallenge, DomainVerificationError, hashClientSecret, verifyDomainChallenge, verifyOwnershipProof } from "./domain-verification";
import type { ScanResponse } from "./transport";

const key = Buffer.from("k".repeat(32));
const secret = "s".repeat(43);
const otherSecret = "x".repeat(43);
const subject = hashClientSecret(secret);
const now = Date.UTC(2026, 7, 27, 12);
const nonce = "n".repeat(43);

function response(body: string, status = 200): ScanResponse {
  return { status, headers: new Headers(), cookies: [], body, finalUrl: new URL("https://example.com/.well-known/africheck-verification.txt") };
}

describe("vérification de domaine", () => {
  it("crée un challenge canonique sans conserver le chemin fourni", () => {
    const result = createDomainChallenge("https://example.com/contact", subject, key, now, nonce);
    expect(result).toMatchObject({ hostname: "example.com", verificationUrl: "https://example.com/.well-known/africheck-verification.txt", expiresAt: "2026-08-27T12:15:00.000Z" });
    expect(result.challenge.split(".")).toHaveLength(2);
  });

  it("rejette un challenge altéré", async () => {
    const created = createDomainChallenge("example.com", subject, key, now, nonce);
    await expect(verifyDomainChallenge({ challenge: `${created.challenge}x`, clientSecret: secret }, key, now, async () => response("")))
      .rejects.toMatchObject({ code: "INVALID_CHALLENGE" });
  });

  it("rejette un challenge expiré avant tout accès réseau", async () => {
    const created = createDomainChallenge("example.com", subject, key, now, nonce);
    await expect(verifyDomainChallenge({ challenge: created.challenge, clientSecret: secret }, key, now + 15 * 60 * 1000, async () => { throw new Error("ne doit pas être appelé"); }))
      .rejects.toMatchObject({ code: "CHALLENGE_EXPIRED" });
  });

  it("lie le challenge au secret détenu par le navigateur", async () => {
    const created = createDomainChallenge("example.com", subject, key, now, nonce);
    await expect(verifyDomainChallenge({ challenge: created.challenge, clientSecret: otherSecret }, key, now, async () => response(created.challenge)))
      .rejects.toMatchObject({ code: "SUBJECT_MISMATCH" });
  });

  it("exige une correspondance exacte du fichier public", async () => {
    const created = createDomainChallenge("example.com", subject, key, now, nonce);
    await expect(verifyDomainChallenge({ challenge: created.challenge, clientSecret: secret }, key, now, async () => response(`${created.challenge}-copie`)))
      .rejects.toMatchObject({ code: "VERIFICATION_FILE_MISMATCH" });
  });

  it("émet une preuve de 30 jours uniquement après validation du fichier", async () => {
    const created = createDomainChallenge("example.com", subject, key, now, nonce);
    let requestedUrl = "";
    const result = await verifyDomainChallenge({ challenge: created.challenge, clientSecret: secret }, key, now, async (url, options) => {
      requestedUrl = url.href;
      expect(options).toEqual({ maxBodyBytes: 4096, timeoutMs: 8000, maxRedirects: 2 });
      return response(`\n${created.challenge}\n`);
    });
    expect(requestedUrl).toBe("https://example.com/.well-known/africheck-verification.txt");
    expect(result.expiresAt).toBe("2026-09-26T12:00:00.000Z");
    expect(verifyOwnershipProof(result.proof, secret, key, now)).toEqual({ hostname: "example.com", subject });
    expect(() => verifyOwnershipProof(result.proof, secret, key, now + 30 * 24 * 60 * 60 * 1000)).toThrow(expect.objectContaining({ code: "PROOF_EXPIRED" }));
  });

  it("refuse les secrets faibles ou mal formés", () => {
    expect(() => hashClientSecret("court")).toThrowError(DomainVerificationError);
  });
});
