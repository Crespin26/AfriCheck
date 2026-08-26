import "server-only";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const blockedHostnames = new Set(["localhost", "localhost.localdomain"]);

function isPrivateIp(address: string): boolean {
  if (address === "::1" || address === "::" || address.startsWith("fe80:") || address.startsWith("fc") || address.startsWith("fd")) return true;
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return false;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
}

export function normalizeUrl(input: string): URL {
  const value = input.trim();
  if (!value || value.length > 2048) throw new Error("Adresse web invalide.");
  const candidate = /^[a-z][a-z\d+.-]*:/i.test(value) ? value : `https://${value}`;
  const url = new URL(candidate);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Seules les adresses HTTP et HTTPS sont acceptées.");
  if (url.username || url.password || url.port) throw new Error("Les identifiants et ports personnalisés ne sont pas acceptés.");
  return url;
}

export async function assertPublicUrl(url: URL): Promise<void> {
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (blockedHostnames.has(hostname) || hostname.endsWith(".local") || hostname.endsWith(".internal")) throw new Error("Cette adresse réseau n’est pas autorisée.");
  const addresses = isIP(hostname) ? [{ address: hostname }] : await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateIp(address))) throw new Error("Cette adresse réseau n’est pas autorisée.");
}
