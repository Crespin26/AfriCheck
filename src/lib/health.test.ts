import { describe, expect, it } from "vitest";
import { readiness } from "./health";

describe("readiness", () => {
  it("accepte une configuration vide et signale la vérification comme désactivée", () => expect(readiness({}, "24.16.0")).toEqual({ ready: true, checks: { runtime: "ok", configuration: "ok", domainVerification: "disabled" } }));
  it("rejette un runtime trop ancien", () => expect(readiness({}, "20.8.0")).toMatchObject({ ready: false, checks: { runtime: "error" } }));
  it("rejette une clé de pseudonymisation trop courte", () => expect(readiness({ LOG_HASH_KEY: "short" }, "24.0.0")).toMatchObject({ ready: false, checks: { configuration: "error" } }));
  it("rejette une valeur proxy ambiguë", () => expect(readiness({ TRUST_PROXY_HEADERS: "yes" }, "24.0.0")).toMatchObject({ ready: false, checks: { configuration: "error" } }));
  it("accepte une clé de vérification robuste", () => expect(readiness({ DOMAIN_VERIFICATION_KEY: "k".repeat(32) }, "24.0.0")).toMatchObject({ ready: true, checks: { domainVerification: "ok" } }));
  it("rejette une clé de vérification trop courte", () => expect(readiness({ DOMAIN_VERIFICATION_KEY: "short" }, "24.0.0")).toMatchObject({ ready: false, checks: { domainVerification: "error" } }));
});
