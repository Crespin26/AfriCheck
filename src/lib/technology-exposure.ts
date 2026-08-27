import "server-only";
import type { Finding } from "./types";

type Exposure = { source: string; value: string; versioned: boolean };

const VERSION_PATTERN = /(?:^|[\s/_(.-])v?\d+(?:\.\d+){1,3}(?:[-+._][a-z0-9]+)?/i;
const HEADER_SIGNALS = [
  ["server", "Serveur HTTP"],
  ["x-powered-by", "Moteur applicatif"],
  ["x-aspnet-version", "Version ASP.NET"],
  ["x-aspnetmvc-version", "Version ASP.NET MVC"],
] as const;
const HTML_SIGNATURES = [
  [/\/(?:wp-content|wp-includes)\//i, "WordPress"],
  [/\/_next\/static\//i, "Next.js"],
  [/(?:drupalSettings|\/sites\/default\/files\/)/i, "Drupal"],
  [/(?:cdn\.shopify\.com|Shopify\.theme)/i, "Shopify"],
] as const;

function safeValue(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, 120);
}

function generatorValue(html: string): string | undefined {
  const tags = html.match(/<meta\b[^>]{0,1000}>/gi) ?? [];
  for (const tag of tags.slice(0, 100)) {
    const name = tag.match(/\bname\s*=\s*["']?([^\s"'>]+)/i)?.[1]?.toLowerCase();
    if (name !== "generator") continue;
    const content = tag.match(/\bcontent\s*=\s*(?:["']([^"']*)["']|([^\s>]+))/i);
    const value = safeValue(content?.[1] ?? content?.[2] ?? "");
    if (value) return value;
  }
  return undefined;
}

export function detectTechnologyExposure(headers: Headers, html: string): Exposure[] {
  const exposures: Exposure[] = [];
  for (const [header, source] of HEADER_SIGNALS) {
    const value = safeValue(headers.get(header) ?? "");
    if (value) exposures.push({ source, value, versioned: VERSION_PATTERN.test(value) });
  }
  const generator = generatorValue(html);
  if (generator) exposures.push({ source: "Générateur HTML", value: generator, versioned: VERSION_PATTERN.test(generator) });
  for (const [pattern, technology] of HTML_SIGNATURES) {
    if (pattern.test(html) && !exposures.some((item) => item.value.toLowerCase().includes(technology.toLowerCase()))) {
      exposures.push({ source: "Empreinte HTML", value: technology, versioned: false });
    }
  }
  return exposures.slice(0, 5);
}

export function technologyExposureFinding(headers: Headers, html: string): Finding {
  const exposures = detectTechnologyExposure(headers, html);
  const versioned = exposures.filter((item) => item.versioned);
  const details = exposures.map((item) => `${item.source} : ${item.value}`).join(" ; ").slice(0, 400);
  if (versioned.length > 0) return {
    id: "technology-exposure", title: "Technologies exposées", status: "warning", points: 0, maxPoints: 5,
    observation: `Des versions logicielles sont publiquement révélées (${details}). Cette empreinte ne prouve pas à elle seule qu’une vulnérabilité est exploitable.`,
    recommendation: "Masquez les numéros de version dans les en-têtes et métadonnées lorsque cela est possible, puis vérifiez les composants dans votre processus de gestion des correctifs.",
  };
  if (exposures.length > 0) return {
    id: "technology-exposure", title: "Technologies exposées", status: "warning", points: 3, maxPoints: 5,
    observation: `Des technologies sont identifiables sans numéro de version explicite (${details}).`,
    recommendation: "Réduisez les en-têtes et métadonnées techniques non nécessaires afin de limiter les informations offertes à un attaquant.",
  };
  return {
    id: "technology-exposure", title: "Technologies exposées", status: "pass", points: 5, maxPoints: 5,
    observation: "Aucun en-tête ni générateur HTML révélant clairement une technologie n’a été observé.",
    recommendation: "Conservez cette réduction d’information et inventoriez les composants côté exploitation.",
  };
}
