import "server-only";
import http from "node:http";
import https from "node:https";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import type { TLSSocket } from "node:tls";
import type { TlsInfo } from "./types";
import { resolvePublicUrl } from "./url-safety";

const MAX_BODY_BYTES = 2_000_000;
const TIMEOUT_MS = 12_000;
const MAX_REDIRECTS = 5;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export type ScanResponse = { status: number; headers: Headers; cookies: string[]; body: string; finalUrl: URL; tls?: TlsInfo; };

function toHeaders(raw: IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(raw)) {
    if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
    else if (value !== undefined) headers.set(name, value);
  }
  return headers;
}

function readBody(response: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    response.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        response.destroy(new Error("La page est trop volumineuse pour ce diagnostic."));
        return;
      }
      chunks.push(chunk);
    });
    response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    response.on("error", reject);
  });
}

async function requestOnce(url: URL): Promise<Omit<ScanResponse, "finalUrl">> {
  const pinned = await resolvePublicUrl(url);
  return new Promise((resolve, reject) => {
    const client = url.protocol === "https:" ? https : http;
    const request = client.request(url, {
      method: "GET",
      headers: { "user-agent": "AfriCheck/0.2 (+https://africheck.app)", accept: "text/html,application/xhtml+xml", "accept-encoding": "identity" },
      rejectUnauthorized: false,
      lookup: (_hostname, _options, callback) => callback(null, pinned.address, pinned.family),
    }, async (response) => {
      try {
        const socket = response.socket as TLSSocket;
        const certificate = url.protocol === "https:" ? socket.getPeerCertificate() : undefined;
        const tls: TlsInfo | undefined = url.protocol === "https:" ? {
          authorized: socket.authorized,
          authorizationError: socket.authorizationError?.toString(),
          validFrom: certificate?.valid_from,
          validTo: certificate?.valid_to,
          protocol: socket.getProtocol(),
        } : undefined;
        resolve({ status: response.statusCode ?? 0, headers: toHeaders(response.headers), cookies: response.headers["set-cookie"] ?? [], body: await readBody(response), tls });
      } catch (error) { reject(error); }
    });
    request.setTimeout(TIMEOUT_MS, () => request.destroy(new Error("Le site met trop de temps à répondre.")));
    request.on("error", reject);
    request.end();
  });
}

export async function fetchWebsite(initial: URL): Promise<ScanResponse> {
  let current = initial;
  for (let count = 0; count <= MAX_REDIRECTS; count += 1) {
    const response = await requestOnce(current);
    if (!REDIRECTS.has(response.status)) return { ...response, finalUrl: current };
    const location = response.headers.get("location");
    if (!location) return { ...response, finalUrl: current };
    current = new URL(location, current);
    if (!["http:", "https:"].includes(current.protocol)) throw new Error("Redirection non autorisée détectée.");
  }
  throw new Error("Le site effectue trop de redirections.");
}
