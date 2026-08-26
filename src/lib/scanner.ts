import "server-only";
import type { Finding, ScanResult } from "./types";
import { assertPublicUrl, normalizeUrl } from "./url-safety";

const securityHeaders = [
  ["strict-transport-security", "HSTS", 12, "Activez HSTS pour imposer HTTPS aux navigateurs."],
  ["content-security-policy", "Content Security Policy", 14, "Définissez une CSP adaptée pour réduire les risques d’injection."],
  ["x-content-type-options", "X-Content-Type-Options", 6, "Ajoutez X-Content-Type-Options: nosniff."],
  ["referrer-policy", "Referrer-Policy", 6, "Définissez une politique de référent restrictive."],
  ["permissions-policy", "Permissions-Policy", 5, "Désactivez les fonctions du navigateur inutilisées."],
] as const;

async function safeFetch(initial: URL): Promise<{ response: Response; finalUrl: URL }> {
  let current = initial;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    await assertPublicUrl(current);
    const response = await fetch(current, { redirect: "manual", signal: AbortSignal.timeout(12_000), headers: { "user-agent": "AfriCheck/0.1 (+https://africheck.app)" } });
    if (![301, 302, 303, 307, 308].includes(response.status)) return { response, finalUrl: current };
    const location = response.headers.get("location");
    if (!location) return { response, finalUrl: current };
    current = new URL(location, current);
    if (!["http:", "https:"].includes(current.protocol)) throw new Error("Redirection non autorisée détectée.");
  }
  throw new Error("Le site effectue trop de redirections.");
}

function grade(score: number): ScanResult["grade"] {
  if (score >= 90) return "A"; if (score >= 75) return "B"; if (score >= 60) return "C"; if (score >= 40) return "D"; return "E";
}

export async function scanWebsite(input: string): Promise<ScanResult> {
  const started = Date.now();
  const url = normalizeUrl(input);
  const { response, finalUrl } = await safeFetch(url);
  if (!response.ok) throw new Error(`Le site a répondu avec le statut HTTP ${response.status}.`);
  const contentType = response.headers.get("content-type") ?? "";
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (contentLength > 2_000_000) throw new Error("La page est trop volumineuse pour ce diagnostic.");
  const html = contentType.includes("text/html") ? (await response.text()).slice(0, 2_000_000) : "";
  const findings: Finding[] = [];
  const https = finalUrl.protocol === "https:";
  findings.push({ id: "https", title: "Connexion HTTPS", status: https ? "pass" : "fail", points: https ? 22 : 0, maxPoints: 22, observation: https ? "La page finale utilise une connexion chiffrée." : "La page finale est accessible sans chiffrement HTTPS.", recommendation: https ? "Aucune action prioritaire." : "Installez un certificat TLS et redirigez tout le trafic HTTP vers HTTPS." });

  for (const [header, title, maxPoints, recommendation] of securityHeaders) {
    const present = response.headers.has(header);
    findings.push({ id: header, title, status: present ? "pass" : "warning", points: present ? maxPoints : 0, maxPoints, observation: present ? `L’en-tête ${title} est présent.` : `L’en-tête ${title} n’a pas été observé.`, recommendation: present ? "Vérifiez régulièrement que sa politique reste adaptée." : recommendation });
  }

  const frameProtected = response.headers.has("x-frame-options") || /frame-ancestors/i.test(response.headers.get("content-security-policy") ?? "");
  findings.push({ id: "frame-protection", title: "Protection anti-clickjacking", status: frameProtected ? "pass" : "warning", points: frameProtected ? 7 : 0, maxPoints: 7, observation: frameProtected ? "Une protection contre l’intégration dans une frame a été observée." : "Aucune protection anti-clickjacking claire n’a été observée.", recommendation: frameProtected ? "Aucune action prioritaire." : "Ajoutez frame-ancestors dans la CSP ou X-Frame-Options." });

  const cookies = response.headers.getSetCookie?.() ?? [];
  const unsafeCookies = cookies.filter((cookie) => !/;\s*secure(?:;|$)/i.test(cookie) || !/;\s*httponly(?:;|$)/i.test(cookie));
  findings.push({ id: "cookies", title: "Protection des cookies", status: unsafeCookies.length ? "warning" : "pass", points: unsafeCookies.length ? 3 : 12, maxPoints: 12, observation: cookies.length === 0 ? "Aucun cookie créé par la réponse initiale." : unsafeCookies.length ? `${unsafeCookies.length} cookie(s) sans Secure ou HttpOnly.` : `${cookies.length} cookie(s) protégé(s) observé(s).`, recommendation: unsafeCookies.length ? "Ajoutez Secure, HttpOnly et un SameSite adapté aux cookies sensibles." : "Contrôlez aussi les cookies créés après authentification." });

  const insecureForms = https ? [...html.matchAll(/<form\b[^>]*action=["'](http:\/\/[^"']+)["']/gi)].length : 0;
  findings.push({ id: "forms", title: "Formulaires chiffrés", status: insecureForms ? "fail" : "pass", points: insecureForms ? 0 : 10, maxPoints: 10, observation: insecureForms ? `${insecureForms} formulaire(s) envoient des données vers HTTP.` : "Aucune action de formulaire explicitement non chiffrée détectée dans la page initiale.", recommendation: insecureForms ? "Envoyez toutes les données de formulaire vers une adresse HTTPS." : "Vérifiez également les formulaires chargés dynamiquement." });

  const max = findings.reduce((sum, item) => sum + item.maxPoints, 0);
  const earned = findings.reduce((sum, item) => sum + item.points, 0);
  const score = Math.round((earned / max) * 100);
  return { url: url.toString(), finalUrl: finalUrl.toString(), scannedAt: new Date().toISOString(), durationMs: Date.now() - started, score, grade: grade(score), findings };
}
