export type Readiness = { ready: boolean; checks: { runtime: "ok" | "error"; configuration: "ok" | "error"; domainVerification: "ok" | "disabled" | "error"; history: "ok" | "disabled" | "error" } };
type RuntimeEnvironment = { TRUST_PROXY_HEADERS?: string; LOG_HASH_KEY?: string; DOMAIN_VERIFICATION_KEY?: string; DATABASE_URL?: string; DATABASE_SSL?: string; HISTORY_RETENTION_DAYS?: string };

export function readiness(env?: RuntimeEnvironment, nodeVersion = process.versions.node): Readiness {
  const environment = env ?? { TRUST_PROXY_HEADERS: process.env.TRUST_PROXY_HEADERS, LOG_HASH_KEY: process.env.LOG_HASH_KEY, DOMAIN_VERIFICATION_KEY: process.env.DOMAIN_VERIFICATION_KEY, DATABASE_URL: process.env.DATABASE_URL, DATABASE_SSL: process.env.DATABASE_SSL, HISTORY_RETENTION_DAYS: process.env.HISTORY_RETENTION_DAYS };
  const [major, minor] = nodeVersion.split(".").map(Number);
  const runtime = major > 20 || (major === 20 && minor >= 9) ? "ok" : "error";
  const proxyValueValid = environment.TRUST_PROXY_HEADERS === undefined || environment.TRUST_PROXY_HEADERS === "true" || environment.TRUST_PROXY_HEADERS === "false";
  const hashKeyValid = environment.LOG_HASH_KEY === undefined || Buffer.byteLength(environment.LOG_HASH_KEY, "utf8") >= 32;
  const configuration = proxyValueValid && hashKeyValid ? "ok" : "error";
  const domainVerification = environment.DOMAIN_VERIFICATION_KEY === undefined ? "disabled" : Buffer.byteLength(environment.DOMAIN_VERIFICATION_KEY, "utf8") >= 32 ? "ok" : "error";
  let history: Readiness["checks"]["history"] = "disabled";
  if (environment.DATABASE_URL !== undefined) {
    const retention = environment.HISTORY_RETENTION_DAYS === undefined ? 90 : Number(environment.HISTORY_RETENTION_DAYS);
    let databaseUrlValid = false;
    try { const url = new URL(environment.DATABASE_URL); databaseUrlValid = ["postgres:", "postgresql:"].includes(url.protocol) && Boolean(url.hostname && url.pathname.slice(1)); } catch { databaseUrlValid = false; }
    const sslValid = environment.DATABASE_SSL === undefined || environment.DATABASE_SSL === "true" || environment.DATABASE_SSL === "false";
    history = databaseUrlValid && sslValid && Number.isInteger(retention) && retention >= 1 && retention <= 365 ? "ok" : "error";
  }
  return { ready: runtime === "ok" && configuration === "ok" && domainVerification !== "error" && history !== "error", checks: { runtime, configuration, domainVerification, history } };
}
