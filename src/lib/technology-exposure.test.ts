import { describe, expect, it } from "vitest";
import { detectTechnologyExposure, technologyExposureFinding } from "./technology-exposure";

describe("empreintes technologiques passives", () => {
  it("récompense une réponse sans empreinte évidente", () => {
    expect(technologyExposureFinding(new Headers(), "<html></html>")).toMatchObject({ status: "pass", points: 5, maxPoints: 5 });
  });

  it("signale les versions exposées sans affirmer une CVE", () => {
    const headers = new Headers({ server: "nginx/1.26.2", "x-powered-by": "PHP/8.3.4" });
    const finding = technologyExposureFinding(headers, "");
    expect(finding).toMatchObject({ status: "warning", points: 0 });
    expect(finding.observation).toContain("nginx/1.26.2");
    expect(finding.observation).toContain("ne prouve pas");
    expect(finding.observation).not.toMatch(/CVE-\d/i);
  });

  it("accorde des points partiels à une technologie sans version", () => {
    expect(technologyExposureFinding(new Headers({ server: "cloudflare" }), "")).toMatchObject({ status: "warning", points: 3 });
  });

  it("détecte un générateur indépendamment de l’ordre des attributs", () => {
    const exposures = detectTechnologyExposure(new Headers(), '<meta content="WordPress 6.6.1" charset="utf-8" name="generator">');
    expect(exposures).toEqual([{ source: "Générateur HTML", value: "WordPress 6.6.1", versioned: true }]);
  });

  it("reconnaît des empreintes HTML sans inventer de version", () => {
    const exposures = detectTechnologyExposure(new Headers(), '<script src="/_next/static/chunks/app.js"></script><img src="/wp-content/logo.png">');
    expect(exposures).toEqual([
      { source: "Empreinte HTML", value: "WordPress", versioned: false },
      { source: "Empreinte HTML", value: "Next.js", versioned: false },
    ]);
  });

  it("neutralise les caractères de contrôle et borne les valeurs non fiables", () => {
    const finding = technologyExposureFinding(new Headers({ server: `nginx/1.2-${"x".repeat(300)}` }), '<meta name="generator" content="WordPress 6.6 <script>">');
    expect(finding.observation).not.toContain("<script>");
    expect(finding.observation.length).toBeLessThanOrEqual(700);
  });
});
