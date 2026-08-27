import http, { type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchWebsite, type TransportOptions } from "./transport";

let server: Server;
let port: number;

beforeEach(async () => {
  server = http.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

function options(overrides: TransportOptions = {}): TransportOptions {
  return { resolveAddress: async () => ({ address: "127.0.0.1", family: 4 }), timeoutMs: 1_000, ...overrides };
}

describe("fetchWebsite", () => {
  it("épingle l’adresse résolue tout en conservant le Host d’origine", async () => {
    server.on("request", (request, response) => {
      response.setHeader("set-cookie", ["a=1; Secure", "b=2; HttpOnly"]);
      response.end(request.headers.host);
    });
    const result = await fetchWebsite(new URL(`http://public.example:${port}/`), options());
    expect(result.body).toBe(`public.example:${port}`);
    expect(result.cookies).toHaveLength(2);
  });

  it("résout et contrôle de nouveau chaque redirection", async () => {
    server.on("request", (request, response) => {
      if (request.url === "/start") { response.writeHead(302, { location: "/final" }); response.end(); return; }
      response.end("ok");
    });
    const resolveAddress = vi.fn(async () => ({ address: "127.0.0.1", family: 4 }));
    const result = await fetchWebsite(new URL(`http://public.example:${port}/start`), options({ resolveAddress }));
    expect(result.finalUrl.pathname).toBe("/final");
    expect(resolveAddress).toHaveBeenCalledTimes(2);
  });

  it("refuse une cible interdite apparue dans une redirection", async () => {
    server.on("request", (_request, response) => { response.writeHead(302, { location: `http://localhost:${port}/private` }); response.end(); });
    const resolveAddress = vi.fn(async (url: URL) => {
      if (url.hostname === "localhost") throw new Error("Cette adresse réseau n’est pas autorisée.");
      return { address: "127.0.0.1", family: 4 };
    });
    await expect(fetchWebsite(new URL(`http://public.example:${port}/`), options({ resolveAddress }))).rejects.toThrow("n’est pas autorisée");
  });

  it("arrête une réponse qui dépasse la limite", async () => {
    server.on("request", (_request, response) => response.end("x".repeat(101)));
    await expect(fetchWebsite(new URL(`http://public.example:${port}/`), options({ maxBodyBytes: 100 }))).rejects.toThrow("trop volumineuse");
  });

  it("interrompt une réponse trop lente", async () => {
    server.on("request", (_request, response) => setTimeout(() => response.end("late"), 100));
    await expect(fetchWebsite(new URL(`http://public.example:${port}/`), options({ timeoutMs: 20 }))).rejects.toThrow("trop de temps");
  });

  it("interrompt aussi une résolution DNS bloquée", async () => {
    const resolveAddress = () => new Promise<never>(() => undefined);
    await expect(fetchWebsite(new URL(`http://public.example:${port}/`), options({ timeoutMs: 20, resolveAddress }))).rejects.toThrow("résolution DNS");
  });

  it("refuse un encodage inattendu au lieu d’analyser des octets compressés", async () => {
    server.on("request", (_request, response) => { response.writeHead(200, { "content-encoding": "gzip" }); response.end("not-really-gzip"); });
    await expect(fetchWebsite(new URL(`http://public.example:${port}/`), options())).rejects.toMatchObject({ code: "UNSUPPORTED_ENCODING" });
  });

  it("limite le nombre de redirections", async () => {
    server.on("request", (request, response) => {
      const count = Number(request.url?.slice(1) || 0);
      response.writeHead(302, { location: `/${count + 1}` }); response.end();
    });
    await expect(fetchWebsite(new URL(`http://public.example:${port}/0`), options({ maxRedirects: 2 }))).rejects.toThrow("trop de redirections");
  });
});
