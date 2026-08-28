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

function attributeValues(tag: string, attribute: string): string[] {
  const expression = new RegExp(`\\b${attribute}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "gi");
  return [...tag.matchAll(expression)].map((match) => match[1] ?? match[2] ?? match[3] ?? "");
}

function countMixedContent(html: string, baseUrl: URL): number {
  const isHttp = (target: string) => {
    try { return new URL(target, baseUrl).protocol === "http:"; }
    catch { return false; }
  };
  let count = 0;
  const countAttribute = (tagPattern: RegExp, attribute: string) => {
    for (const [tag] of html.matchAll(tagPattern)) count += attributeValues(tag, attribute).filter(isHttp).length;
  };
  countAttribute(/<(?:script|img|iframe|audio|video|source|track|embed|input)\b[^>]*>/gi, "src");
  countAttribute(/<link\b[^>]*>/gi, "href");
  countAttribute(/<object\b[^>]*>/gi, "data");
  countAttribute(/<video\b[^>]*>/gi, "poster");
  for (const [tag] of html.matchAll(/<(?:img|source)\b[^>]*>/gi)) {
    for (const sourceSet of attributeValues(tag, "srcset")) count += [...sourceSet.matchAll(/(?:^|,)\s*(http:\/\/[^\s,]+)/gi)].length;
  }
  const cssFragments = [
    ...[...html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style\s*>/gi)].map((match) => match[1]),
    ...[...html.matchAll(/<[^>]+>/g)].flatMap(([tag]) => attributeValues(tag, "style")),
  ];
  for (const css of cssFragments) {
    for (const match of css.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^\s)]+))\s*\)/gi)) {
      if (isHttp(match[1] ?? match[2] ?? match[3] ?? "")) count += 1;
    }
  }
  return count;
}

function cookieIsProtected(cookie: string, https: boolean): boolean {
  if (!https) return false;
  const segments = cookie.split(";").map((segment) => segment.trim());
  const separator = segments[0]?.indexOf("=") ?? -1;
  if (separator <= 0) return false;
  const name = segments[0].slice(0, separator);
  const attributes = segments.slice(1);
  const hasFlag = (flag: string) => attributes.some((attribute) => attribute.toLowerCase() === flag);
  const attributeValue = (key: string) => attributes.find((attribute) => attribute.toLowerCase().startsWith(`${key}=`))?.slice(key.length + 1).trim();
  const secure = hasFlag("secure");
  const httpOnly = hasFlag("httponly");
  const sameSite = attributeValue("samesite")?.toLowerCase();
  if (!secure || !httpOnly || !sameSite || !["strict", "lax", "none"].includes(sameSite)) return false;
  if (name.startsWith("__Secure-") && !secure) return false;
  if (name.startsWith("__Host-") && (!secure || attributeValue("path") !== "/" || attributeValue("domain") !== undefined)) return false;
  return true;
}

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

function analyzeHsts(header: string, https: boolean): Finding {
  const maxAgeMatch = header.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i);
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : undefined;
  const strong = https && maxAge !== undefined && maxAge >= 15_552_000;
  const partial = https && maxAge !== undefined && maxAge > 0;
  return {
    id: "strict-transport-security", title: "HSTS", status: strong ? "pass" : partial ? "warning" : "fail", points: strong ? 10 : partial ? 5 : 0, maxPoints: 10,
    observation: !https ? "HSTS ne peut pas être activé par une réponse HTTP." : strong ? "HSTS impose HTTPS pendant au moins 180 jours." : partial ? "HSTS est actif mais sa durée est inférieure à 180 jours." : header ? "HSTS est invalide ou désactivé par max-age=0." : "HSTS n’a pas été observé.",
    recommendation: strong ? "Envisagez includeSubDomains après validation de tous les sous-domaines." : "Servez le site via HTTPS et ajoutez Strict-Transport-Security avec un max-age d’au moins 15552000.",
  };
}

function cspIsWeak(header: string): boolean {
  const directives = new Map<string, string[]>();
  for (const rawDirective of header.split(";")) {
    const [rawName, ...rawSources] = rawDirective.trim().split(/\s+/);
    const name = rawName?.toLowerCase();
    if (name && !directives.has(name)) directives.set(name, rawSources.map((source) => source.toLowerCase()));
  }
  const baseScripts = directives.get("script-src") ?? directives.get("default-src");
  if (!baseScripts) return true;
  const scriptPolicies = [directives.get("script-src-elem") ?? baseScripts, directives.get("script-src-attr") ?? baseScripts];
  const dangerousScriptSources = new Set(["*", "'unsafe-inline'", "'unsafe-eval'", "http:", "https:", "data:", "blob:"]);
  if (scriptPolicies.some((sources) => sources.some((source) => dangerousScriptSources.has(source)))) return true;
  return [...directives.entries()].some(([name, sources]) => (name.endsWith("-src") || name === "frame-ancestors") && sources.includes("*"));
}

export function analyzeResponse(url: URL, response: ScanResponse): Finding[] {
  const findings: Finding[] = [];
  const https = response.finalUrl.protocol === "https:";
  add(findings, { id: "https", title: "Connexion HTTPS", status: https ? "pass" : "fail", points: https ? 15 : 0, maxPoints: 15, observation: https ? "La page finale utilise une connexion chiffrée." : "La page finale est accessible sans chiffrement HTTPS.", recommendation: https ? "Aucune action prioritaire." : "Redirigez tout le trafic HTTP vers HTTPS." });
  add(findings, analyzeTls(response.tls, https));

  const hsts = response.headers.get("strict-transport-security") ?? "";
  add(findings, analyzeHsts(hsts, https));

  const csp = response.headers.get("content-security-policy") ?? "";
  const weakCsp = csp ? cspIsWeak(csp) : false;
  add(findings, { id: "content-security-policy", title: "Content Security Policy", status: !csp ? "fail" : weakCsp ? "warning" : "pass", points: !csp ? 0 : weakCsp ? 6 : 12, maxPoints: 12, observation: !csp ? "Aucune CSP n’a été observée." : weakCsp ? "Une CSP existe mais autorise des sources ou mécanismes de script permissifs." : "Une CSP structurée a été observée.", recommendation: !csp ? "Définissez une CSP adaptée pour réduire les risques d’injection." : weakCsp ? "Retirez les jokers, schémas génériques, unsafe-inline et unsafe-eval ; privilégiez des nonces ou hashes." : "Testez régulièrement la politique et surveillez les violations." });

  const nosniff = response.headers.get("x-content-type-options")?.toLowerCase() === "nosniff";
  add(findings, { id: "x-content-type-options", title: "X-Content-Type-Options", status: nosniff ? "pass" : "warning", points: nosniff ? 5 : 0, maxPoints: 5, observation: nosniff ? "La valeur nosniff est active." : "La valeur nosniff n’a pas été observée.", recommendation: nosniff ? "Aucune action prioritaire." : "Ajoutez X-Content-Type-Options: nosniff." });

  const referrer = response.headers.get("referrer-policy")?.toLowerCase() ?? "";
  const safeReferrer = Boolean(referrer && !referrer.includes("unsafe-url"));
  add(findings, { id: "referrer-policy", title: "Referrer-Policy", status: safeReferrer ? "pass" : "warning", points: safeReferrer ? 5 : 0, maxPoints: 5, observation: safeReferrer ? `Politique observée : ${referrer}.` : "Aucune politique restrictive valide n’a été observée.", recommendation: safeReferrer ? "Aucune action prioritaire." : "Utilisez strict-origin-when-cross-origin ou une politique plus restrictive." });

  const permissions = response.headers.get("permissions-policy");
  add(findings, { id: "permissions-policy", title: "Permissions-Policy", status: permissions ? "pass" : "warning", points: permissions ? 3 : 0, maxPoints: 3, observation: permissions ? "Une politique de permissions est définie." : "Aucune politique de permissions n’a été observée.", recommendation: permissions ? "Vérifiez qu’elle désactive les fonctions inutilisées." : "Désactivez les fonctions du navigateur inutilisées." });

  const frameProtected = /^(deny|sameorigin)$/i.test(response.headers.get("x-frame-options") ?? "") || /frame-ancestors\s+[^;]+/i.test(csp);
  add(findings, { id: "frame-protection", title: "Protection anti-clickjacking", status: frameProtected ? "pass" : "warning", points: frameProtected ? 5 : 0, maxPoints: 5, observation: frameProtected ? "Une directive anti-clickjacking valide a été observée." : "Aucune protection anti-clickjacking claire n’a été observée.", recommendation: frameProtected ? "Aucune action prioritaire." : "Ajoutez frame-ancestors dans la CSP ou X-Frame-Options." });

  const cookieIssues = response.cookies.filter((cookie) => !cookieIsProtected(cookie, https));
  add(findings, { id: "cookies", title: "Protection des cookies", status: cookieIssues.length ? "warning" : "pass", points: cookieIssues.length ? 3 : 10, maxPoints: 10, observation: response.cookies.length === 0 ? "Aucun cookie créé par la réponse initiale." : cookieIssues.length ? `${cookieIssues.length} cookie(s) sans transport ou attributs de protection complets.` : `${response.cookies.length} cookie(s) correctement protégé(s) observé(s).`, recommendation: cookieIssues.length ? "Utilisez HTTPS, Secure, HttpOnly, un SameSite adapté et respectez les contraintes des préfixes __Host- ou __Secure-." : "Contrôlez aussi les cookies créés après authentification." });

  const html = response.headers.get("content-type")?.includes("text/html") ? response.body : "";
  const forms = [...html.matchAll(/<form\b[^>]*>/gi)].map(([tag]) => tag);
  const insecureForms = forms.filter((tag) => {
    if (!https) return true;
    const action = tag.match(/\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const target = action?.[1] ?? action?.[2] ?? action?.[3];
    if (!target) return false;
    try { return new URL(target, response.finalUrl).protocol !== "https:"; }
    catch { return true; }
  }).length;
  add(findings, {
    id: "forms", title: "Formulaires chiffrés", status: insecureForms ? "fail" : "pass", points: insecureForms ? 0 : 10, maxPoints: 10,
    observation: insecureForms ? `${insecureForms} formulaire(s) peuvent transmettre des données sans HTTPS.` : forms.length ? `${forms.length} formulaire(s) utilisent une destination HTTPS.` : "Aucun formulaire détecté dans le HTML initial.",
    recommendation: insecureForms ? "Servez la page et la destination de chaque formulaire exclusivement via HTTPS." : "Vérifiez également les formulaires chargés dynamiquement.",
  });

  const mixed = https ? countMixedContent(html, response.finalUrl) : 0;
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
