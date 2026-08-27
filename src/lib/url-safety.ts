import "server-only";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

export type ResolvedAddress = { address: string; family: number };
export type Resolver = (hostname: string) => Promise<ResolvedAddress[]>;

const blockedHostnames = new Set(["localhost", "localhost.localdomain"]);
const blocked = new BlockList();

for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4],
] as const) blocked.addSubnet(network, prefix, "ipv4");

for (const [network, prefix] of [
  ["::", 128], ["::1", 128], ["64:ff9b::", 96],
  ["100::", 64], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
] as const) blocked.addSubnet(network, prefix, "ipv6");

export function isPublicIp(address: string): boolean {
  if (address.toLowerCase().startsWith("::ffff:")) return false;
  const family = isIP(address);
  return family === 4 ? !blocked.check(address, "ipv4") : family === 6 ? !blocked.check(address, "ipv6") : false;
}

export function normalizeUrl(input: string): URL {
  const value = input.trim();
  if (!value || value.length > 2048) throw new Error("Adresse web invalide.");
  const candidate = /^[a-z][a-z\d+.-]*:/i.test(value) ? value : `https://${value}`;
  let url: URL;
  try { url = new URL(candidate); } catch { throw new Error("Adresse web invalide."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Seules les adresses HTTP et HTTPS sont acceptées.");
  if (url.username || url.password || url.port) throw new Error("Les identifiants et ports personnalisés ne sont pas acceptés.");
  return url;
}

const defaultResolver: Resolver = async (hostname) => lookup(hostname, { all: true, verbatim: true });

export async function resolvePublicUrl(url: URL, resolver: Resolver = defaultResolver): Promise<ResolvedAddress> {
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (blockedHostnames.has(hostname) || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
    throw new Error("Cette adresse réseau n’est pas autorisée.");
  }
  const family = isIP(hostname);
  const addresses = family ? [{ address: hostname, family }] : await resolver(hostname);
  if (!addresses.length || addresses.some(({ address }) => !isPublicIp(address))) throw new Error("Cette adresse réseau n’est pas autorisée.");
  return addresses[0];
}
