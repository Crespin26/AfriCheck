import { describe, expect, it } from "vitest";
import { analyzeResponse, scoreFindings } from "./scanner";
import { isEvaluatedFinding, remediationPriorities } from "./report";
import type { ScanResponse } from "./transport";

const url = new URL("https://public.example/");
const validTls = { authorized: true, validTo: "2035-01-01T00:00:00Z" };
function inspect(body: string, options: Partial<ScanResponse> = {}) {
  return analyzeResponse(url, { status: 200, finalUrl: url, body,
    headers: new Headers({ "content-type": "text/html" }), cookies: [], tls: validTls, ...options });
}
const finding = (body: string, id: string, options?: Partial<ScanResponse>) => inspect(body, options).find((item) => item.id === id)!;

describe("régressions de fiabilité du diagnostic", () => {
  it("ne donne aucun point aux éléments absents et calcule sur le périmètre évalué", () => {
    const findings = inspect("<html></html>");
    for (const id of ["cookies", "forms", "mixed-content", "technology-exposure"]) {
      expect(findings.find((item) => item.id === id)).toMatchObject({ status: "not_observed", points: 0 });
    }
    expect(findings.filter(isEvaluatedFinding)).toHaveLength(8);
    expect(scoreFindings(findings)).toEqual({ score: 38, grade: "E" }); // 25/65, never 60/100 from unobserved checks.
    expect(remediationPriorities(findings, 20).every(isEvaluatedFinding)).toBe(true);
  });

  it.each(["application/json", "application/xhtml+xml", "image/png", ""])("ne valide pas les formulaires ou ressources d’un contenu %s", (contentType) => {
    const findings = inspect('<form action="http://public.example"><img src="http://public.example/image">', { headers: new Headers(contentType ? { "content-type": contentType } : {}) });
    for (const id of ["forms", "mixed-content"]) expect(findings.find((item) => item.id === id)?.status).toBe("unavailable");
  });

  it.each([
    '<!-- <form action="http://public.example"><img src="http://public.example/i"> -->',
    '<script>const example = \'<form action="http://public.example"><img src="http://public.example/i">\';</script>',
    '<template><form action="http://public.example"><img src="http://public.example/i"></form></template>',
  ])("ignore les fausses balises dans un contenu inactif : %s", (body) => {
    expect(finding(body, "forms").status).toBe("not_observed");
    expect(finding(body, "mixed-content").status).toBe("not_observed");
  });

  it("résout les actions et ressources relatives selon la première balise base", () => {
    const body = '<base href="http://public.example/"><base href="https://public.example/"><form action="submit"></form><img src="image.png">';
    expect(finding(body, "forms").status).toBe("fail");
    expect(finding(body, "mixed-content").status).toBe("fail");
    expect(finding('<base href="http://public.example/"><form></form>', "forms").status).toBe("pass");
  });

  it("décode les entités HTML et respecte les caractères > dans un attribut", () => {
    const body = '<form title="a > b" action="h&#116;tp://public.example/submit"></form><img alt="a > b" src="h&#116;tp://public.example/image">';
    expect(finding(body, "forms").status).toBe("fail");
    expect(finding(body, "mixed-content").status).toBe("fail");
  });

  it("inspecte les destinations des boutons associés, même hors du formulaire", () => {
    const body = '<form id="payment" action="/safe"></form><button type="unknown" form="payment" formaction="http://public.example/unsafe">Payer</button>';
    expect(finding(body, "forms").status).toBe("fail");
    expect(finding('<form method="dialog"></form>', "forms").status).toBe("not_applicable");
  });

  it("ne confond pas les liens canoniques ou de navigation avec des ressources chargées", () => {
    expect(finding('<link rel="canonical" href="http://public.example/"><a href="http://public.example/">Lien</a>', "mixed-content").status).toBe("not_observed");
  });

  it("résout les candidats srcset et distingue les URL data des requêtes réseau", () => {
    expect(finding('<base href="http://public.example/"><img srcset="image.png 1x, large.png 2x">', "mixed-content").status).toBe("fail");
    expect(finding('<img src="data:image/png;base64,AAAA" srcset="data:image/png;base64,AAAA 1x">', "mixed-content").status).toBe("not_observed");
  });

  it("ignore les commentaires et chaînes CSS mais décode les vrais url() échappés", () => {
    const safe = '<style>/* url(http://public.example/fake) */ p::before { content: "url(http://public.example/fake)"; } :root { --unused: url(http://public.example/unused); }</style>';
    expect(finding(safe, "mixed-content").status).toBe("not_observed");
    expect(finding(String.raw`<style>p { background: url(h\74 tp://public.example/image); }</style>`, "mixed-content").status).toBe("fail");
    expect(finding('<style>p { background: image-set("http://public.example/image" 1x); }</style>', "mixed-content").status).toBe("fail");
  });

  it("rend explicites les limites de CSS non résolu", () => {
    expect(finding('<style>:root { --image: url(http://public.example/image); } p { background: var(--image); }</style>', "mixed-content").status).toBe("unavailable");
  });

  it("inspecte les ressources SVG et signale les documents intégrés non analysés", () => {
    expect(finding('<svg><image href="http://public.example/image" /></svg>', "mixed-content").status).toBe("fail");
    expect(finding('<iframe srcdoc="&lt;form&gt;&lt;/form&gt;"></iframe>', "forms").status).toBe("unavailable");
    expect(finding('<div><template shadowrootmode="open"><img src="http://public.example/image"></template></div>', "mixed-content").status).toBe("unavailable");
  });

  it("ne traite pas une instruction de suppression comme un cookie actif non protégé", () => {
    expect(finding("", "cookies", { cookies: ["old=; Max-Age=0", "other=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"] }).status).toBe("not_observed");
    expect(finding("", "cookies", { cookies: ["session=value; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT"] }).status).toBe("warning");
  });

  it("ne valide pas un en-tête HSTS contradictoire", () => {
    expect(finding("", "strict-transport-security", { headers: new Headers({ "strict-transport-security": "max-age=31536000; max-age=0" }) }).status).toBe("fail");
  });

  it("ne présente pas les politiques de document absentes d’une réponse JSON comme des défauts vérifiés", () => {
    const findings = inspect("{}", { headers: new Headers({ "content-type": "application/json" }) });
    for (const id of ["content-security-policy", "frame-protection", "permissions-policy", "referrer-policy"]) {
      expect(findings.find((item) => item.id === id)?.status).toBe("unavailable");
    }
  });

  it("signale un certificat qui arrive prochainement à expiration", () => {
    expect(finding("", "tls", { tls: { authorized: true, validTo: new Date(Date.now() + 10 * 86_400_000).toISOString() } })).toMatchObject({ status: "warning", points: 6 });
  });

  it("ne transforme pas des informations TLS manquantes en certificat invalide", () => {
    expect(finding("", "tls", { tls: undefined }).status).toBe("unavailable");
    expect(finding("", "tls", { tls: { authorized: true } }).status).toBe("unavailable");
    expect(finding("", "tls", { tls: { authorized: true, validTo: new Date(Date.now() - 1000).toISOString() } }).status).toBe("fail");
    expect(finding("", "tls", { tls: { ...validTls, validFrom: "2034-01-01T00:00:00Z" } }).status).toBe("fail");
  });

  it("plafonne une bonne configuration de surface lorsqu’un certificat est invalide", () => {
    const findings = inspect("", { tls: { ...validTls, authorized: false, authorizationError: "CERT_HAS_EXPIRED" } });
    // Make every other evaluated check pass to expose the critical cap.
    const otherwisePerfect = findings.map((item) => item.id === "tls" ? item : { ...item, status: "pass" as const, points: item.maxPoints });
    expect(scoreFindings(otherwisePerfect)).toEqual({ score: 49, grade: "D" });
  });

  it("conserve le signal d’un cookie et d’un certificat problématiques avant une redirection", () => {
    const findings = inspect('<form action="/"></form>', { redirects: [{ url, destination: url,
      cookies: ["session=secret"], tls: { ...validTls, authorized: false, authorizationError: "CERT_HAS_EXPIRED" } }] });
    expect(findings.find((item) => item.id === "cookies")?.status).toBe("warning");
    expect(findings.find((item) => item.id === "tls")?.status).toBe("fail");
  });
});
