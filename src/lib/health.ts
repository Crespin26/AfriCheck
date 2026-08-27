export type Readiness = { ready: boolean; checks: { runtime: "ok" | "error"; configuration: "ok" | "error"; domainVerification: "ok" | "disabled" | "error" } };
type RuntimeEnvironment = { TRUST_PROXY_HEADERS?: string; LOG_HASH_KEY?: string; DOMAIN_VERIFICATION_KEY?: string };

export function readiness(env?: RuntimeEnvironment, nodeVersion = process.versions.node): Readiness {
  const environment = env ?? { TRUST_PROXY_HEADERS: process.env.TRUST_PROXY_HEADERS, LOG_HASH_KEY: process.env.LOG_HASH_KEY, DOMAIN_VERIFICATION_KEY: process.env.DOMAIN_VERIFICATION_KEY };
  const [major, minor] = nodeVersion.split(".").map(Number);
  const runtime = major > 20 || (major === 20 && minor >= 9) ? "ok" : "error";
  const proxyValueValid = environment.TRUST_PROXY_HEADERS === undefined || environment.TRUST_PROXY_HEADERS === "true" || environment.TRUST_PROXY_HEADERS === "false";
  const hashKeyValid = environment.LOG_HASH_KEY === undefined || Buffer.byteLength(environment.LOG_HASH_KEY, "utf8") >= 32;
  const configuration = proxyValueValid && hashKeyValid ? "ok" : "error";
  const domainVerification = environment.DOMAIN_VERIFICATION_KEY === undefined ? "disabled" : Buffer.byteLength(environment.DOMAIN_VERIFICATION_KEY, "utf8") >= 32 ? "ok" : "error";
  return { ready: runtime === "ok" && configuration === "ok" && domainVerification !== "error", checks: { runtime, configuration, domainVerification } };
}
