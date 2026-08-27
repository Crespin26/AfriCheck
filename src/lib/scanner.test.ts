import { describe, expect, it } from "vitest";
import type { Finding } from "./types";
import type { ScanResponse } from "./transport";
import { analyzeResponse, scoreFindings } from "./scanner";

const future = new Date(Date.now() + 90 * 86_400_000).toUTCString();

function response(overrides: Partial<ScanResponse> = {}): ScanResponse {
  return {
    status: 200,
    finalUrl: new URL("https://example.com"),
    headers: new Headers({
      "content-type": "text/html",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=()",
    }),
    cookies: ["session=abc; Secure; HttpOnly; SameSite=Lax"], body: "<html></html>",
    tls: { authorized: true, validTo: future, protocol: "TLSv1.3" }, ...overrides,
  };
}

describe("scoreFindings", () => {
  it("calcule le pourcentage et la note", () => {
    const findings = [{ points: 9, maxPoints: 10 }, { points: 8, maxPoints: 10 }] as Finding[];
    expect(scoreFindings(findings)).toEqual({ score: 85, grade: "B" });
  });
  it("borne les points et gère une liste vide", () => {
    expect(scoreFindings([])).toEqual({ score: 0, grade: "E" });
    expect(scoreFindings([{ points: 20, maxPoints: 10 }] as Finding[]).score).toBe(100);
  });
});

describe("analyzeResponse", () => {
  it("produit 100 points maximum et valide une réponse solide", () => {
    const findings = analyzeResponse(new URL("https://example.com"), response());
    expect(findings.reduce((sum, item) => sum + item.maxPoints, 0)).toBe(100);
    expect(scoreFindings(findings)).toEqual({ score: 100, grade: "A" });
  });
  it("détecte contenu mixte, formulaire HTTP et cookies incomplets", () => {
    const findings = analyzeResponse(new URL("https://example.com"), response({ cookies: ["session=abc; Secure"], body: '<form action="http://example.com/login"><script src="http://cdn.example.com/app.js"></script>' }));
    expect(findings.find((item) => item.id === "forms")?.status).toBe("fail");
    expect(findings.find((item) => item.id === "mixed-content")?.status).toBe("fail");
    expect(findings.find((item) => item.id === "cookies")?.status).toBe("warning");
  });
  it("signale un certificat expiré et une CSP permissive", () => {
    const headers = response().headers;
    headers.set("content-security-policy", "default-src * 'unsafe-inline'");
    const findings = analyzeResponse(new URL("https://example.com"), response({ headers, tls: { authorized: false, authorizationError: "CERT_HAS_EXPIRED", validTo: "Jan 1 2020 GMT" } }));
    expect(findings.find((item) => item.id === "tls")?.status).toBe("fail");
    expect(findings.find((item) => item.id === "content-security-policy")?.status).toBe("warning");
  });
});
