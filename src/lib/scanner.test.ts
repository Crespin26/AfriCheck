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
  it("distingue les ressources mixtes des simples liens de navigation", () => {
    const safe = analyzeResponse(new URL("https://example.com"), response({ body: '<a href="http://example.net">Documentation</a>' }));
    expect(safe.find((item) => item.id === "mixed-content")?.status).toBe("pass");
    const unsafe = analyzeResponse(new URL("https://example.com"), response({ body: '<img src=http://cdn.example.com/a.png srcset="https://cdn.example.com/a.png 1x, http://cdn.example.com/a@2x.png 2x"><style>.hero{background:url(http://cdn.example.com/bg.png)}</style><link href="http://cdn.example.com/app.css">' }));
    expect(unsafe.find((item) => item.id === "mixed-content")).toMatchObject({ status: "fail", points: 0 });
    expect(unsafe.find((item) => item.id === "mixed-content")?.observation).toContain("4 ressource(s)");
  });
  it("considère tous les formulaires d’une page HTTP comme non chiffrés", () => {
    const headers = response().headers;
    headers.delete("strict-transport-security");
    const findings = analyzeResponse(new URL("https://example.com"), response({ finalUrl: new URL("http://example.com"), headers, tls: undefined, body: '<form action="/connexion"><form>' }));
    expect(findings.find((item) => item.id === "forms")).toMatchObject({ status: "fail", points: 0 });
    expect(findings.find((item) => item.id === "forms")?.observation).toContain("2 formulaire(s)");
  });
  it("accepte une action relative sur HTTPS mais détecte une action HTTP non quotée", () => {
    const safe = analyzeResponse(new URL("https://example.com"), response({ body: '<form action="/connexion">' }));
    expect(safe.find((item) => item.id === "forms")?.status).toBe("pass");
    const unsafe = analyzeResponse(new URL("https://example.com"), response({ body: "<form action=http://example.com/connexion>" }));
    expect(unsafe.find((item) => item.id === "forms")?.status).toBe("fail");
    const nonWeb = analyzeResponse(new URL("https://example.com"), response({ body: '<form action="mailto:contact@example.com">' }));
    expect(nonWeb.find((item) => item.id === "forms")?.status).toBe("fail");
  });
  it("signale un certificat expiré et une CSP permissive", () => {
    const headers = response().headers;
    headers.set("content-security-policy", "default-src * 'unsafe-inline'");
    const findings = analyzeResponse(new URL("https://example.com"), response({ headers, tls: { authorized: false, authorizationError: "CERT_HAS_EXPIRED", validTo: "Jan 1 2020 GMT" } }));
    expect(findings.find((item) => item.id === "tls")?.status).toBe("fail");
    expect(findings.find((item) => item.id === "content-security-policy")?.status).toBe("warning");
  });
});
