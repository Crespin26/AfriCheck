import { describe, expect, it } from "vitest";
import { ScanError, toPublicError } from "./errors";

describe("toPublicError", () => {
  it("préserve uniquement les erreurs métier typées", () => {
    expect(toPublicError(new ScanError("TARGET_BLOCKED", "détail interne à ne pas exposer"))).toEqual({ code: "TARGET_BLOCKED", message: "Cette adresse réseau n’est pas autorisée.", status: 422 });
  });
  it("reconnaît une erreur sérialisée issue d’un autre contexte", () => {
    expect(toPublicError({ name: "ScanError", code: "REQUEST_TIMEOUT", message: "détail provenant d’un worker", httpStatus: 504 })).toEqual({ code: "REQUEST_TIMEOUT", message: "Le site met trop de temps à répondre.", status: 504 });
  });
  it("refuse un faux code ou statut hors limites", () => {
    expect(toPublicError({ name: "ScanError", code: "LEAK_SECRET", message: "secret", httpStatus: 200 }).code).toBe("INTERNAL_ERROR");
  });
  it("neutralise les détails d’une erreur inconnue", () => {
    const result = toPublicError(new Error("token=secret dans /internal/path"));
    expect(result).toEqual({ code: "INTERNAL_ERROR", message: "Une erreur interne empêche temporairement le diagnostic.", status: 500 });
  });
  it("classe les erreurs réseau sans exposer leur contenu", () => expect(toPublicError(new Error("connect ECONNREFUSED 10.0.0.1"))).toMatchObject({ code: "UPSTREAM_UNREACHABLE", status: 502 }));
});
