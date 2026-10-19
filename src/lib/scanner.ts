import "server-only";
import type { Finding, ScanResult, TlsInfo } from "./types";
import { fetchWebsite, type ScanResponse } from "./transport";
import { normalizeUrl } from "./url-safety";
import { ScanError } from "./errors";
import { inspectHtml } from "./html-inspection";
import { isEvaluatedFinding } from "./report";
import { technologyExposureFinding } from "./technology-exposure";

/**
 * Calcule le pourcentage sur les seuls contrôles évalués, puis attribue une note de A à E.
 * Un échec HTTPS ou TLS plafonne le score à 49, quelles que soient les autres protections.
 */
export function scoreFindings(findings: Finding[]): Pick<ScanResult, "score" | "grade"> {
  const evaluated = findings.filter(isEvaluatedFinding);
  const maximum = evaluated.reduce((sum, item) => sum + item.maxPoints, 0);
  const earned = evaluated.reduce((sum, item) => sum + Math.min(item.maxPoints, Math.max(0, item.points)), 0);
  const rawScore = maximum > 0 ? Math.round((earned / maximum) * 100) : 0;
  const criticalTransportFailure = findings.some((item) => ["https", "tls"].includes(item.id) && item.status === "fail");
  const score = criticalTransportFailure ? Math.min(49, rawScore) : rawScore;
  const grade: ScanResult["grade"] = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "E";
  return { score, grade };
}

/**
 * Ajoute un constat à la liste des contrôles du diagnostic.
 */
function add(findings: Finding[], finding: Finding) { findings.push(finding); }

/**
 * Vérifie les attributs de protection attendus d’un cookie et la cohérence de SameSite=None avec Secure.
 */
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

/**
 * Évalue le certificat observé et sa période de validité, ou indique que le contrôle est indisponible.
 */
function analyzeTls(tls: TlsInfo | undefined, https: boolean): Finding {
  if (!https) return { id: "tls", title: "Certificat TLS", status: "not_applicable", points: 0, maxPoints: 10, observation: "La page HTTP ne présente pas de certificat TLS.", recommendation: "Passez la page à HTTPS pour protéger la connexion." };
  const expiry = tls?.validTo ? Date.parse(tls.validTo) : NaN;
  if (!tls || (tls.authorized && !Number.isFinite(expiry))) return {
    id: "tls", title: "Certificat TLS", status: "unavailable", points: 0, maxPoints: 10,
    observation: "Les informations du certificat ne permettent pas de vérifier sa validité et son expiration.", recommendation: "Contrôlez le certificat avec un outil TLS dédié.",
  };
  const days = Math.ceil((expiry - Date.now()) / 86_400_000);
  const notBefore = tls.validFrom ? Date.parse(tls.validFrom) : undefined;
  const valid = Boolean(tls.authorized && expiry > Date.now() && (notBefore === undefined || (Number.isFinite(notBefore) && notBefore <= Date.now())));
  const expiring = valid && days! <= 30;
  return {
    id: "tls", title: "Certificat TLS", status: valid ? (expiring ? "warning" : "pass") : "fail", points: valid ? (expiring ? 6 : 10) : 0, maxPoints: 10,
    observation: !valid ? `Le certificat n’est pas valide${tls?.authorizationError ? ` (${tls.authorizationError})` : ""}.` : expiring ? `Le certificat expire dans ${days} jour(s).` : `Le certificat est valide encore ${days} jour(s)${tls?.protocol ? ` via ${tls.protocol}` : ""}.`,
    recommendation: !valid ? "Renouvelez ou corrigez la chaîne du certificat TLS." : expiring ? "Renouvelez le certificat avant son expiration." : "Conservez le renouvellement automatique et surveillez son expiration.",
  };
}

/**
 * Contrôle la présence et la durée de HSTS en tenant compte de HTTPS et des directives max-age ambiguës.
 */
function analyzeHsts(header: string, https: boolean): Finding {
  const duplicateMaxAge = [...header.matchAll(/(?:^|;)\s*max-age\s*=/gi)].length > 1;
  const maxAgeMatch = header.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i);
  const maxAge = !duplicateMaxAge && maxAgeMatch ? Number(maxAgeMatch[1]) : undefined;
  const strong = https && maxAge !== undefined && maxAge >= 15_552_000;
  const partial = https && maxAge !== undefined && maxAge > 0;
  return {
    id: "strict-transport-security", title: "HSTS", status: strong ? "pass" : partial ? "warning" : "fail", points: strong ? 10 : partial ? 5 : 0, maxPoints: 10,
    observation: !https ? "HSTS ne peut pas être activé par une réponse HTTP." : strong ? "HSTS impose HTTPS pendant au moins 180 jours." : partial ? "HSTS est actif mais sa durée est inférieure à 180 jours." : header ? "HSTS est invalide ou désactivé par max-age=0." : "HSTS n’a pas été observé.",
    recommendation: strong ? "Envisagez includeSubDomains après validation de tous les sous-domaines." : "Servez le site via HTTPS et ajoutez Strict-Transport-Security avec un max-age d’au moins 15552000.",
  };
}

/**
 * Repère les sources et mécanismes de script jugés permissifs dans la politique CSP observée.
 */
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

/**
 * Classe la politique de transmission du référent selon les valeurs reconnues dans l’en-tête.
 */
function analyzeReferrerPolicy(header: string): Finding {
  const recognized = new Set(["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"]);
  const effective = header.split(",").map((value) => value.trim().toLowerCase()).reverse().find((value) => recognized.has(value));
  const restrictive = effective !== undefined && ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"].includes(effective);
  return {
    id: "referrer-policy", title: "Referrer-Policy", status: restrictive ? "pass" : "warning", points: restrictive ? 5 : 0, maxPoints: 5,
    observation: restrictive ? `Politique effective : ${effective}.` : effective ? `La politique effective ${effective} peut divulguer trop d’informations.` : "Aucune politique restrictive valide n’a été observée.",
    recommendation: restrictive ? "Aucune action prioritaire." : "Utilisez strict-origin-when-cross-origin ou une politique plus restrictive.",
  };
}

/**
 * Examine les restrictions déclarées pour les fonctionnalités sensibles prises en compte par ce contrôle.
 */
function analyzePermissionsPolicy(header: string): Finding {
  const directives = new Map<string, string>();
  let invalid = false;
  for (const rawDirective of header.split(",")) {
    const match = rawDirective.trim().match(/^([a-z][a-z0-9-]*)\s*=\s*(\([^)]*\)|\*)$/i);
    if (!match || directives.has(match[1].toLowerCase())) { invalid = true; continue; }
    directives.set(match[1].toLowerCase(), match[2].toLowerCase());
  }
  const sensitive = ["camera", "microphone", "geolocation", "payment", "usb"];
  const restrictive = Boolean(header) && !invalid && sensitive.every((feature) => {
    const allowlist = directives.get(feature);
    return allowlist !== undefined && !allowlist.includes("*");
  });
  return {
    id: "permissions-policy", title: "Permissions-Policy", status: restrictive ? "pass" : "warning", points: restrictive ? 3 : 0, maxPoints: 3,
    observation: restrictive ? "Les capacités sensibles principales sont limitées explicitement." : header ? "La politique ne limite pas explicitement toutes les capacités sensibles principales." : "Aucune politique de permissions n’a été observée.",
    recommendation: restrictive ? "Réévaluez cette liste lorsque les fonctionnalités du site évoluent." : "Limitez au minimum camera, microphone, geolocation, payment et usb sans joker.",
  };
}

/**
 * Recherche une directive frame-ancestors exploitable pour évaluer la protection contre l’intégration en iframe.
 */
function cspFrameProtection(header: string): boolean | undefined {
  const directive = header.split(";").map((value) => value.trim()).find((value) => /^frame-ancestors(?:\s|$)/i.test(value));
  if (directive === undefined) return undefined;
  const [, ...sources] = directive.split(/\s+/);
  const broadSources = new Set(["*", "http:", "https:", "data:"]);
  return sources.length > 0 && sources.every((source) => !broadSources.has(source.toLowerCase()));
}

/**
 * Transforme la réponse finale et les redirections observées en constats de sécurité.
 * L’analyse reste statique : elle n’exécute pas JavaScript et ne charge pas les ressources référencées.
 */
export function analyzeResponse(url: URL, response: ScanResponse): Finding[] {
  const findings: Finding[] = [];
  const https = response.finalUrl.protocol === "https:";
  const downgraded = (response.redirects ?? []).some((hop) => hop.url.protocol === "https:" && hop.destination.protocol === "http:");
  add(findings, { id: "https", title: "Connexion HTTPS", status: !https || downgraded ? "fail" : "pass", points: !https || downgraded ? 0 : 15, maxPoints: 15,
    observation: downgraded ? "La navigation observée contient une redirection HTTPS vers HTTP." : !https ? "La page finale est accessible sans chiffrement HTTPS." : url.protocol === "http:" ? "La navigation commencée en HTTP aboutit à une page HTTPS." : "La page finale utilise HTTPS ; une entrée initiale en HTTP n’a pas été testée.",
    recommendation: !https || downgraded ? "Imposez HTTPS et supprimez les redirections vers HTTP." : "Maintenez HTTPS sur toute la navigation et vérifiez aussi le point d’entrée HTTP." });
  const tlsChecks = [
    ...((response.redirects ?? []).filter((hop) => hop.url.protocol === "https:").map((hop) => analyzeTls(hop.tls, true))),
    analyzeTls(response.tls, https),
  ];
  const tlsFinding = tlsChecks.find((item) => item.status === "fail") ?? tlsChecks.find((item) => item.status === "unavailable") ?? tlsChecks.find((item) => item.status === "warning") ?? tlsChecks.find((item) => item.status === "pass") ?? tlsChecks.at(-1)!;
  add(findings, { ...tlsFinding, observation: tlsChecks.length > 1 ? `${tlsFinding.observation} Les connexions TLS des redirections observées sont incluses.` : tlsFinding.observation });

  const hsts = response.headers.get("strict-transport-security") ?? "";
  add(findings, analyzeHsts(hsts, https));

  const csp = response.headers.get("content-security-policy") ?? "";
  const weakCsp = csp ? cspIsWeak(csp) : false;
  add(findings, { id: "content-security-policy", title: "Content Security Policy", status: !csp ? "fail" : weakCsp ? "warning" : "pass", points: !csp ? 0 : weakCsp ? 6 : 12, maxPoints: 12, observation: !csp ? "Aucune CSP n’a été observée." : weakCsp ? "Une CSP existe mais autorise des sources ou mécanismes de script permissifs." : "Une CSP structurée a été observée.", recommendation: !csp ? "Définissez une CSP adaptée pour réduire les risques d’injection." : weakCsp ? "Retirez les jokers, schémas génériques, unsafe-inline et unsafe-eval ; privilégiez des nonces ou hashes." : "Testez régulièrement la politique et surveillez les violations." });

  const nosniff = response.headers.get("x-content-type-options")?.toLowerCase() === "nosniff";
  add(findings, { id: "x-content-type-options", title: "X-Content-Type-Options", status: nosniff ? "pass" : "warning", points: nosniff ? 5 : 0, maxPoints: 5, observation: nosniff ? "La valeur nosniff est active." : "La valeur nosniff n’a pas été observée.", recommendation: nosniff ? "Aucune action prioritaire." : "Ajoutez X-Content-Type-Options: nosniff." });

  add(findings, analyzeReferrerPolicy(response.headers.get("referrer-policy") ?? ""));

  add(findings, analyzePermissionsPolicy(response.headers.get("permissions-policy") ?? ""));

  const cspFrameProtected = cspFrameProtection(csp);
  const frameProtected = cspFrameProtected ?? /^(deny|sameorigin)$/i.test(response.headers.get("x-frame-options") ?? "");
  add(findings, { id: "frame-protection", title: "Protection anti-clickjacking", status: frameProtected ? "pass" : "warning", points: frameProtected ? 5 : 0, maxPoints: 5, observation: frameProtected ? "Une directive anti-clickjacking valide a été observée." : "Aucune protection anti-clickjacking claire n’a été observée.", recommendation: frameProtected ? "Aucune action prioritaire." : "Ajoutez frame-ancestors dans la CSP ou X-Frame-Options." });

  const cookies = [
    ...response.cookies.map((cookie) => ({ cookie, https })),
    ...(response.redirects ?? []).flatMap((hop) => hop.cookies.map((cookie) => ({ cookie, https: hop.url.protocol === "https:" }))),
  ];
  const activeCookies = cookies.filter(({ cookie }) => {
    const attributes = cookie.split(";").slice(1).map((value) => value.trim());
    const age = attributes.find((value) => /^max-age=/i.test(value))?.slice(8);
    if (age !== undefined && /^-?\d+$/.test(age)) return Number(age) > 0;
    const expiry = attributes.find((value) => /^expires=/i.test(value))?.slice(8);
    return expiry === undefined || !Number.isFinite(Date.parse(expiry)) || Date.parse(expiry) > Date.now();
  });
  const cookieIssues = activeCookies.filter((item) => !cookieIsProtected(item.cookie, item.https));
  add(findings, { id: "cookies", title: "Protection des cookies", status: !activeCookies.length ? "not_observed" : cookieIssues.length ? "warning" : "pass", points: !activeCookies.length ? 0 : cookieIssues.length ? 3 : 10, maxPoints: 10,
    observation: !activeCookies.length ? cookies.length ? "Seules des instructions de suppression de cookies ont été reçues ; aucun cookie actif n’a été évalué." : "Aucun cookie reçu pendant la navigation observée. Les cookies créés par JavaScript ou après connexion ne sont pas vérifiés." : cookieIssues.length ? `${cookieIssues.length} cookie(s) sans transport ou attributs de protection complets, redirections comprises.` : `${activeCookies.length} cookie(s) avec les attributs de protection attendus dans les réponses observées.`,
    recommendation: cookieIssues.length ? "Utilisez HTTPS, Secure, HttpOnly pour les cookies sensibles, et un SameSite adapté ; respectez les préfixes défensifs." : "Contrôlez aussi les cookies créés par JavaScript ou après authentification." });

  const mediaType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  const html = mediaType === "text/html" ? response.body : undefined;
  const inspected = html === undefined ? undefined : inspectHtml(html, response.finalUrl);
  const unavailableHtml = mediaType === "application/xhtml+xml" ? "Le document XHTML nécessite une analyse XML non prise en charge." : "Le type de contenu ne permet pas d’inspecter une page HTML.";
  let insecureActions = 0;
  let unknownActions = inspected?.formIncomplete ?? false;
  for (const action of inspected?.formActions ?? []) {
    const target = new URL(action);
    if (!["http:", "https:"].includes(target.protocol)) unknownActions = true;
    else if (!https || target.protocol === "http:") insecureActions += 1;
  }
  const formsStatus = !inspected ? "unavailable" : insecureActions ? "fail" : unknownActions ? "unavailable" : !inspected.hasForms ? "not_observed" : !inspected.formActions.length ? "not_applicable" : "pass";
  add(findings, {
    id: "forms", title: "Formulaires chiffrés", status: formsStatus, points: formsStatus === "pass" ? 10 : 0, maxPoints: 10,
    observation: !inspected ? unavailableHtml : insecureActions ? `${insecureActions} destination(s) de formulaire peuvent transmettre des données sans protection HTTPS, y compris via un bouton de soumission.` : unknownActions ? "Certaines destinations de formulaire ne permettent pas une vérification HTTP(S) complète." : !inspected.hasForms ? "Aucun formulaire détecté dans le HTML initial ; aucun chiffrement de formulaire n’a été vérifié." : !inspected.formActions.length ? "Les formulaires observés ne soumettent pas de données sur le réseau (method=dialog)." : `${inspected.formActions.length} destination(s) de formulaire utilisent HTTPS depuis une page HTTPS.`,
    recommendation: insecureActions ? "Servez la page et toutes les destinations de soumission exclusivement via HTTPS." : "Vérifiez également les formulaires chargés dynamiquement et les parcours authentifiés.",
  });

  let mixed = 0;
  let webResources = 0;
  let resourceIncomplete = inspected?.resourceIncomplete ?? false;
  for (const source of inspected?.resourceUrls ?? []) {
    try {
      const target = new URL(source, inspected!.baseUrl);
      if (["http:", "https:"].includes(target.protocol)) { webResources += 1; if (target.protocol === "http:") mixed += 1; }
    } catch { resourceIncomplete = true; }
  }
  const mixedStatus = !https ? "not_applicable" : !inspected ? "unavailable" : mixed ? "fail" : resourceIncomplete ? "unavailable" : !webResources ? "not_observed" : "pass";
  add(findings, { id: "mixed-content", title: "Contenu mixte", status: mixedStatus, points: mixedStatus === "pass" ? 10 : 0, maxPoints: 10,
    observation: !https ? "La page utilise HTTP ; le contrôle de contenu mixte s’applique aux pages HTTPS." : !inspected ? unavailableHtml : mixed ? `${mixed} ressource(s) HTTP référencée(s) depuis la page HTTPS. Leur chargement effectif dépend du navigateur et de la CSP.` : resourceIncomplete ? "Certaines références de ressources ou règles CSS ne permettent pas une analyse complète." : !webResources ? "Aucune ressource HTTP(S) à évaluer dans le HTML et le CSS intégrés inspectés." : "Les références HTTP(S) inspectées utilisent HTTPS. Les ressources dynamiques et le contenu des fichiers externes ne sont pas vérifiés.",
    recommendation: mixed ? "Remplacez les références HTTP par HTTPS, y compris dans la balise base, les srcset et les styles intégrés." : "Vérifiez également les ressources injectées par JavaScript et celles des feuilles de style externes." });
  add(findings, technologyExposureFinding(response.headers, html, inspected));
  if (!["text/html", "application/xhtml+xml"].includes(mediaType ?? "")) {
    for (const item of findings) {
      if (["content-security-policy", "frame-protection", "referrer-policy", "permissions-policy"].includes(item.id)) {
        Object.assign(item, { status: "unavailable", points: 0,
          observation: "Le contenu reçu n’est pas identifié comme un document HTML ou XHTML ; l’applicabilité de cette politique de page ne peut pas être vérifiée.",
          recommendation: "Relancez le diagnostic sur une page HTML du site pour évaluer cette protection de page.",
        });
      }
    }
  }
  return findings;
}

/**
 * Normalise la cible, récupère sa réponse avec les protections réseau, puis assemble le diagnostic et son score v2.
 */
export async function scanWebsite(input: string): Promise<ScanResult> {
  const started = Date.now();
  const url = normalizeUrl(input);
  const response = await fetchWebsite(url);
  if (response.status < 200 || response.status >= 400) throw new ScanError("UPSTREAM_HTTP_ERROR", `Le site a répondu avec le statut HTTP ${response.status}.`, 502);
  const findings = analyzeResponse(url, response);
  return { url: url.toString(), finalUrl: response.finalUrl.toString(), scannedAt: new Date().toISOString(), durationMs: Date.now() - started, ...scoreFindings(findings), findings, scoringVersion: 2 };
}
