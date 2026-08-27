import { describe, expect, it } from "vitest";
import { isPublicIp, normalizeUrl, resolvePublicUrl } from "./url-safety";

describe("normalizeUrl", () => {
  it("ajoute HTTPS quand le protocole manque", () => expect(normalizeUrl("example.com/path").toString()).toBe("https://example.com/path"));
  it.each(["file:///etc/passwd", "ftp://example.com", "https://user:pass@example.com", "https://example.com:8443"])("rejette %s", (value) => expect(() => normalizeUrl(value)).toThrow());
});

describe("isPublicIp", () => {
  it.each(["127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.168.1.1", "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1"])("bloque %s", (address) => expect(isPublicIp(address)).toBe(false));
  it.each(["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])("accepte %s", (address) => expect(isPublicIp(address)).toBe(true));
});

describe("resolvePublicUrl", () => {
  it("rejette si une réponse DNS contient aussi une IP privée", async () => {
    const resolver = async () => [{ address: "1.1.1.1", family: 4 }, { address: "127.0.0.1", family: 4 }];
    await expect(resolvePublicUrl(new URL("https://example.com"), resolver)).rejects.toThrow("n’est pas autorisée");
  });
  it("retourne l’adresse publique qui sera épinglée par le transport", async () => {
    const resolver = async () => [{ address: "1.1.1.1", family: 4 }];
    await expect(resolvePublicUrl(new URL("https://example.com"), resolver)).resolves.toEqual({ address: "1.1.1.1", family: 4 });
  });
});
