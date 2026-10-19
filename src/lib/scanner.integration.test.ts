import http, { type IncomingMessage, type RequestListener } from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { scanWebsite } from "./scanner";

// Only redirect DNS/ports for our own fixture hostname. No external site is contacted,
// and the actual transport, TLS handshakes, redirects and scanner run unchanged.
vi.mock("./url-safety", async (importOriginal) => {
  const original = await importOriginal<typeof import("./url-safety")>();
  return { ...original, resolvePublicUrl: (url: URL) => ["public.example", "other.public.example"].includes(url.hostname)
    ? Promise.resolve({ address: "127.0.0.1", family: 4 }) : original.resolvePublicUrl(url) };
});

const fixture = (name: string) => readFileSync(new URL(`../../test/fixtures/scanner/${name}.pem`, import.meta.url));
const ca = fixture("ca");
const key = fixture("server-key");
const valid = fixture("valid");
const expired = fixture("expired");
const realHttpRequest = http.request;
const realHttpsRequest = https.request;

const handler: RequestListener = (request, response) => {
  const secure = "encrypted" in request.socket;
  if (request.url === "/upgrade") {
    response.writeHead(301, { location: "https://public.example/strong", "set-cookie": "session=unprotected" });
    response.end(); return;
  }
  if (request.url === "/downgrade") {
    response.writeHead(302, { location: "http://public.example/plain" }); response.end(); return;
  }
  if (request.url === "/loop") {
    response.writeHead(302, { location: "/loop" }); response.end(); return;
  }
  if (request.url === "/private") {
    response.writeHead(302, { location: "http://127.0.0.1/" }); response.end(); return;
  }
  response.setHeader("content-type", request.url === "/json" ? "application/json" : "text/html");
  response.setHeader("strict-transport-security", "max-age=31536000");
  response.setHeader("content-security-policy", "default-src 'self'; frame-ancestors 'none'");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  if (request.url === "/strong") response.setHeader("set-cookie", "session=protected; Secure; HttpOnly; SameSite=Lax");
  response.end(request.url === "/json" ? '{"markup":"<form>"}' : request.url === "/empty" ? "<html></html>"
    : `<html><body><form action="/submit"></form><img src="${secure ? "https" : "http"}://public.example/image.png"></body></html>`);
};
const httpServer = http.createServer(handler);
const tlsServer = https.createServer({ key, cert: valid }, handler);

beforeAll(async () => {
  await Promise.all([httpServer, tlsServer].map((server) => new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))));
});
beforeEach(() => {
  tlsServer.setSecureContext({ key, cert: valid });
  vi.spyOn(http, "request").mockImplementation(((url: URL, options: http.RequestOptions, callback: (response: IncomingMessage) => void) => {
    const routed = new URL(url); routed.port = String((httpServer.address() as AddressInfo).port);
    return realHttpRequest(routed, { ...options, agent: false }, callback);
  }) as typeof http.request);
  vi.spyOn(https, "request").mockImplementation(((url: URL, options: https.RequestOptions, callback: (response: IncomingMessage) => void) => {
    const routed = new URL(url); routed.port = String((tlsServer.address() as AddressInfo).port);
    return realHttpsRequest(routed, { ...options, ca, agent: false }, callback);
  }) as typeof https.request);
});
afterEach(() => vi.restoreAllMocks());
afterAll(async () => {
  await Promise.all([httpServer, tlsServer].map((server) => {
    server.closeAllConnections();
    return new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }));
});

describe("diagnostics de serveurs HTTP/TLS contrôlés", () => {
  it("vérifie un certificat réellement valide, les cookies, formulaires et ressources HTTPS", async () => {
    const result = await scanWebsite("https://public.example/strong");
    expect(result).toMatchObject({ score: 100, grade: "A", scoringVersion: 2 });
    for (const id of ["tls", "cookies", "forms", "mixed-content"]) expect(result.findings.find((item) => item.id === id)?.status).toBe("pass");
  });
  it("détecte un certificat réellement expiré et plafonne la note", async () => {
    tlsServer.setSecureContext({ key, cert: expired });
    const result = await scanWebsite("https://public.example/strong");
    expect(result.findings.find((item) => item.id === "tls")).toMatchObject({ status: "fail" });
    expect(result.findings.find((item) => item.id === "tls")?.observation).toContain("CERT_HAS_EXPIRED");
    expect(result.score).toBe(49);
  });
  it("détecte réellement un certificat valide pour un autre nom d’hôte", async () => {
    const result = await scanWebsite("https://other.public.example/strong");
    expect(result.findings.find((item) => item.id === "tls")).toMatchObject({ status: "fail" });
    expect(result.findings.find((item) => item.id === "tls")?.observation).toContain("ERR_TLS_CERT_ALTNAME_INVALID");
    expect(result.score).toBe(49);
  });
  it("conserve un cookie HTTP problématique malgré une redirection vers HTTPS", async () => {
    const result = await scanWebsite("http://public.example/upgrade");
    expect(result.finalUrl).toBe("https://public.example/strong");
    expect(result.findings.find((item) => item.id === "https")?.status).toBe("pass");
    expect(result.findings.find((item) => item.id === "cookies")?.status).toBe("warning");
  });
  it("signale une rétrogradation HTTPS vers HTTP sans prétendre vérifier du contenu mixte", async () => {
    const result = await scanWebsite("https://public.example/downgrade");
    expect(result.findings.find((item) => item.id === "https")?.status).toBe("fail");
    expect(result.findings.find((item) => item.id === "forms")?.status).toBe("fail");
    expect(result.findings.find((item) => item.id === "mixed-content")?.status).toBe("not_applicable");
    expect(result.score).toBeLessThanOrEqual(49);
  });
  it("ne confond pas une page vide ou une réponse JSON avec des protections vérifiées", async () => {
    const empty = await scanWebsite("https://public.example/empty");
    expect(empty.findings.find((item) => item.id === "forms")?.status).toBe("not_observed");
    const json = await scanWebsite("https://public.example/json");
    expect(json.findings.find((item) => item.id === "forms")?.status).toBe("unavailable");
  });
  it("arrête les boucles de redirection et conserve les protections anti-SSRF", async () => {
    await expect(scanWebsite("https://public.example/loop")).rejects.toMatchObject({ code: "TOO_MANY_REDIRECTS" });
    await expect(scanWebsite("https://public.example/private")).rejects.toMatchObject({ code: "TARGET_BLOCKED" });
  });
});
