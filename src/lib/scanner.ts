import "server-only";
import type { Finding, ScanResult, TlsInfo } from "./types";
import { fetchWebsite, type ScanResponse } from "./transport";
import { normalizeUrl } from "./url-safety";
import { ScanError } from "./errors";
import { technologyExposureFinding } from "./technology-exposure";

export function scoreFindings(findings: Finding[]): Pick<ScanResult, "score" | "grade"> {
  const maximum = findings.reduce((sum, item) => sum + item.maxPoints, 0);
  const earned = findings.reduce((sum, item) => sum + Math.min(item.maxPoints, Math.max(0, item.points)), 0);
  const score = maximum > 0 ? Math.round((earned / maximum) * 100) : 0;
  const grade: ScanResult["grade"] = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "E";
  return { score, grade };
}

function add(findings: Finding[], finding: Finding) { findings.push(finding); }

function analyzeTls(tls: TlsInfo | undefined, https: boolean): Finding {
  if (!https) return { id: "tls", title: "Certificat TLS", status: "fail", points: 0, maxPoints: 10, observation: "Aucun certificat TLS n’est utilisé.", recommendation: "Installez un certificat TLS reconnu et configurez son renouvellement automatique." };
  const expiry = tls?.validTo ? new Date(tls.validTo) : undefined;
  const days = expiry ? Math.ceil((expiry.getTime() - Date.now()) / 86_400_000) : undefined;
  const valid = Boolean(tls?.authorized && days !== undefined && days > 0);
  const expiring = valid && days! <= 30;
  return {
    id: "tls", title: "Certificat TLS", status: valid ? (expiring ? "warning" : "pass") : "fail", points: valid ? (expiring ? 6 : 10) : 0, maxPoints: 10,
    observation: !valid ? `Le certificat n’est pas valide${tls?.authorizationError ? ` (${tls.authorizationError})` : ""}.` : expiring ? `Le certificat expire dans ${days} jour(s).` : `Le certificat est valide encore ${days} jour(s)${tls?.protocol ? ` via ${tls.protocol}` : ""}.`,
    recommendation: !valid ? "Renouvelez ou corrigez la chaîne du certificat TLS." : expiring ? "Renouvelez le certificat avant son expiration." : "Conservez le renouvellement automatique et surveillez son expiration.",
  };
}

export function analyzeResponse(url: URL, response: ScanResponse): Finding[] {
  const findings: Finding[] = [];
  const https = response.finalUrl.protocol === "https:";
  add(findings, { id: "https", title: "Connexion HTTPS", status: https ? "pass" : "fail", points: https ? 15 : 0, maxPoints: 15, observation: https ? "La page finale utilise une connexion chiffrée." : "La page finale est accessible sans chiffrement HTTPS.", recommendation: https ? "Aucune action prioritaire." : "Redirigez tout le trafic HTTP vers HTTPS." });
  add(findings, analyzeTls(response.tls, https));

  const hsts = response.headers.get("strict-transport-security") ?? "";
  const hstsAge = Number(hsts.match(/max-age\s*=\s*(\d+)/i)?.[1] ?? 0);
  const strongHsts = https && hstsAge >= 15_552_000;
  add(findings, { id: "strict-transport-security", title: "HSTS", status: strongHsts ? "pass" : hsts ? "warning" : "fail", points: strongHsts ? 10 : hsts ? 5 : 0, maxPoints: 10, observation: strongHsts ? "HSTS impose HTTPS pendant au moins 180 jours." : hsts ? "HSTS est présent mais sa durée est trop courte ou invalide." : "HSTS n’a pas été observé.", recommendation: strongHsts ? "Envisagez includeSubDomains après validation de tous les sous-domaines." : "Ajoutez Strict-Transport-Security avec un max-age d’au moins 15552000." });

  const csp = response.headers.get("content-security-policy") ?? "";
  const weakCsp = /unsafe-inline|\*\s*(?:;|$)/i.test(csp) || !/default-src|script-src/i.test(csp);
  add(findings, { id: "content-security-policy", title: "Content Security Policy", status: !csp ? "fail" : weakCsp ? "warning" : "pass", points: !csp ? 0 : weakCsp ? 6 : 12, maxPoints: 12, observation: !csp ? "Aucune CSP n’a été observée." : weakCsp ? "Une CSP existe mais contient des règles permissives." : "Une CSP structurée a été observée.", recommendation: !csp ? "Définissez une CSP adaptée pour réduire les risques d’injection." : weakCsp ? "Réduisez les jokers et unsafe-inline ; privilégiez des nonces ou hashes." : "Testez régulièrement la politique et surveillez les violations." });

  const nosniff = response.headers.get("x-content-type-options")?.toLowerCase() === "nosniff";
  add(findings, { id: "x-content-type-options", title: "X-Content-Type-Options", status: nosniff ? "pass" : "warning", points: nosniff ? 5 : 0, maxPoints: 5, observation: nosniff ? "La valeur nosniff est active." : "La valeur nosniff n’a pas été observée.", recommendation: nosniff ? "Aucune action prioritaire." : "Ajoutez X-Content-Type-Options: nosniff." });

  const referrer = response.headers.get("referrer-policy")?.toLowerCase() ?? "";
  const safeReferrer = Boolean(referrer && !referrer.includes("unsafe-url"));
  add(findings, { id: "referrer-policy", title: "Referrer-Policy", status: safeReferrer ? "pass" : "warning", points: safeReferrer ? 5 : 0, maxPoints: 5, observation: safeReferrer ? `Politique observée : ${referrer}.` : "Aucune politique restrictive valide n’a été observée.", recommendation: safeReferrer ? "Aucune action prioritaire." : "Utilisez strict-origin-when-cross-origin ou une politique plus restrictive." });

  const permissions = response.headers.get("permissions-policy");
  add(findings, { id: "permissions-policy", title: "Permissions-Policy", status: permissions ? "pass" : "warning", points: permissions ? 3 : 0, maxPoints: 3, observation: permissions ? "Une politique de permissions est définie." : "Aucune politique de permissions n’a été observée.", recommendation: permissions ? "Vérifiez qu’elle désactive les fonctions inutilisées." : "Désactivez les fonctions du navigateur inutilisées." });

  const frameProtected = /^(deny|sameorigin)$/i.test(response.headers.get("x-frame-options") ?? "") || /frame-ancestors\s+[^;]+/i.test(csp);
  add(findings, { id: "frame-protection", title: "Protection anti-clickjacking", status: frameProtected ? "pass" : "warning", points: frameProtected ? 5 : 0, maxPoints: 5, observation: frameProtected ? "Une directive anti-clickjacking valide a été observée." : "Aucune protection anti-clickjacking claire n’a été observée.", recommendation: frameProtected ? "Aucune action prioritaire." : "Ajoutez frame-ancestors dans la CSP ou X-Frame-Options." });

  const cookieIssues = response.cookies.filter((cookie) => !/;\s*secure(?:;|$)/i.test(cookie) || !/;\s*httponly(?:;|$)/i.test(cookie) || !/;\s*samesite=(strict|lax|none)(?:;|$)/i.test(cookie));
  add(findings, { id: "cookies", title: "Protection des cookies", status: cookieIssues.length ? "warning" : "pass", points: cookieIssues.length ? 3 : 10, maxPoints: 10, observation: response.cookies.length === 0 ? "Aucun cookie créé par la réponse initiale." : cookieIssues.length ? `${cookieIssues.length} cookie(s) sans protection complète Secure, HttpOnly et SameSite.` : `${response.cookies.length} cookie(s) correctement protégé(s) observé(s).`, recommendation: cookieIssues.length ? "Ajoutez Secure, HttpOnly et un SameSite adapté aux cookies sensibles." : "Contrôlez aussi les cookies créés après authentification." });

  const html = response.headers.get("content-type")?.includes("text/html") ? response.body : "";
  const insecureForms = https ? [...html.matchAll(/<form\b[^>]*action\s*=\s*["']http:\/\/[^"']+["']/gi)].length : 0;
  add(findings, { id: "forms", title: "Formulaires chiffrés", status: insecureForms ? "fail" : "pass", points: insecureForms ? 0 : 10, maxPoints: 10, observation: insecureForms ? `${insecureForms} formulaire(s) envoient des données vers HTTP.` : "Aucune action de formulaire explicitement non chiffrée détectée.", recommendation: insecureForms ? "Envoyez toutes les données de formulaire vers une adresse HTTPS." : "Vérifiez également les formulaires chargés dynamiquement." });

  const mixed = https ? [...html.matchAll(/(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi)].length : 0;
  add(findings, { id: "mixed-content", title: "Contenu mixte", status: mixed ? "fail" : "pass", points: mixed ? 0 : 10, maxPoints: 10, observation: mixed ? `${mixed} ressource(s) HTTP référencée(s) depuis la page HTTPS.` : "Aucune ressource HTTP explicite détectée dans le HTML initial.", recommendation: mixed ? "Servez toutes les images, scripts et feuilles de style via HTTPS." : "Vérifiez aussi les ressources injectées dynamiquement." });
  add(findings, technologyExposureFinding(response.headers, html));
  return findings;
}

export async function scanWebsite(input: string): Promise<ScanResult> {
  const started = Date.now();
  const url = normalizeUrl(input);
  const response = await fetchWebsite(url);
  if (response.status < 200 || response.status >= 400) throw new ScanError("UPSTREAM_HTTP_ERROR", `Le site a répondu avec le statut HTTP ${response.status}.`, 502);
  const findings = analyzeResponse(url, response);
  return { url: url.toString(), finalUrl: response.finalUrl.toString(), scannedAt: new Date().toISOString(), durationMs: Date.now() - started, ...scoreFindings(findings), findings };
}
