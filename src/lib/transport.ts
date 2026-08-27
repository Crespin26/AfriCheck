import "server-only";
import http from "node:http";
import https from "node:https";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import type { TLSSocket } from "node:tls";
import type { TlsInfo } from "./types";
import { resolvePublicUrl, type ResolvedAddress } from "./url-safety";

const MAX_BODY_BYTES = 2_000_000;
const TIMEOUT_MS = 12_000;
const MAX_REDIRECTS = 5;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export type ScanResponse = { status: number; headers: Headers; cookies: string[]; body: string; finalUrl: URL; tls?: TlsInfo; };
export type TransportOptions = {
  resolveAddress?: (url: URL) => Promise<ResolvedAddress>;
  maxBodyBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
};

type RequiredTransportOptions = Required<TransportOptions>;

function optionsWithDefaults(options: TransportOptions): RequiredTransportOptions {
  return {
    resolveAddress: options.resolveAddress ?? resolvePublicUrl,
    maxBodyBytes: options.maxBodyBytes ?? MAX_BODY_BYTES,
    timeoutMs: options.timeoutMs ?? TIMEOUT_MS,
    maxRedirects: options.maxRedirects ?? MAX_REDIRECTS,
  };
}

function toHeaders(raw: IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(raw)) {
    if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
    else if (value !== undefined) headers.set(name, value);
  }
  return headers;
}

function readBody(response: IncomingMessage, maxBodyBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    response.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBodyBytes) {
        response.destroy(new Error("La page est trop volumineuse pour ce diagnostic."));
        return;
      }
      chunks.push(chunk);
    });
    response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    response.on("error", reject);
  });
}

async function requestOnce(url: URL, options: RequiredTransportOptions): Promise<Omit<ScanResponse, "finalUrl">> {
  const started = Date.now();
  const pinned = await new Promise<ResolvedAddress>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("La résolution DNS met trop de temps à répondre.")), options.timeoutMs);
    options.resolveAddress(url).then(
      (address) => { clearTimeout(timer); resolve(address); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
  const remainingMs = Math.max(1, options.timeoutMs - (Date.now() - started));
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = <T,>(callback: (value: T) => void, value: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      callback(value);
    };
    const client = url.protocol === "https:" ? https : http;
    const request = client.request(url, {
      method: "GET",
      headers: { "user-agent": "AfriCheck/0.2 (+https://africheck.app)", accept: "text/html,application/xhtml+xml", "accept-encoding": "identity" },
      rejectUnauthorized: false,
      lookup: (_hostname, lookupOptions, callback) => {
        if (lookupOptions.all) callback(null, [pinned]);
        else callback(null, pinned.address, pinned.family);
      },
    }, async (response) => {
      try {
        const encoding = response.headers["content-encoding"]?.toLowerCase();
        if (encoding && encoding !== "identity") {
          response.destroy();
          throw new Error(`L’encodage de réponse ${encoding} n’est pas pris en charge.`);
        }
        const socket = response.socket as TLSSocket;
        const certificate = url.protocol === "https:" ? socket.getPeerCertificate() : undefined;
        const tls: TlsInfo | undefined = url.protocol === "https:" ? {
          authorized: socket.authorized,
          authorizationError: socket.authorizationError?.toString(),
          validFrom: certificate?.valid_from,
          validTo: certificate?.valid_to,
          protocol: socket.getProtocol(),
        } : undefined;
        const result = { status: response.statusCode ?? 0, headers: toHeaders(response.headers), cookies: response.headers["set-cookie"] ?? [], body: await readBody(response, options.maxBodyBytes), tls };
        finish(resolve, result);
      } catch (error) { finish(reject, error); }
    });
    const deadline = setTimeout(() => request.destroy(new Error("Le site met trop de temps à répondre.")), remainingMs);
    request.on("error", (error) => finish(reject, error));
    request.end();
  });
}

export async function fetchWebsite(initial: URL, overrides: TransportOptions = {}): Promise<ScanResponse> {
  const options = optionsWithDefaults(overrides);
  let current = initial;
  for (let count = 0; count <= options.maxRedirects; count += 1) {
    const response = await requestOnce(current, options);
    if (!REDIRECTS.has(response.status)) return { ...response, finalUrl: current };
    const location = response.headers.get("location");
    if (!location) return { ...response, finalUrl: current };
    current = new URL(location, current);
    if (!["http:", "https:"].includes(current.protocol)) throw new Error("Redirection non autorisée détectée.");
  }
  throw new Error("Le site effectue trop de redirections.");
}
