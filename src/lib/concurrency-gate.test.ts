import { describe, expect, it } from "vitest";
import { ConcurrencyGate, scanConcurrencyLimit } from "./concurrency-gate";

describe("ConcurrencyGate", () => {
  it("rejette immédiatement au plafond puis réutilise une place libérée", () => {
    const gate = new ConcurrencyGate(2);
    const releaseFirst = gate.tryAcquire();
    const releaseSecond = gate.tryAcquire();
    expect(releaseFirst).toBeTypeOf("function");
    expect(releaseSecond).toBeTypeOf("function");
    expect(gate.tryAcquire()).toBeUndefined();
    releaseFirst?.();
    expect(gate.tryAcquire()).toBeTypeOf("function");
  });

  it("rend la libération idempotente", () => {
    const gate = new ConcurrencyGate(1);
    const release = gate.tryAcquire();
    release?.();
    release?.();
    expect(gate.tryAcquire()).toBeTypeOf("function");
    expect(gate.tryAcquire()).toBeUndefined();
  });
});

describe("scanConcurrencyLimit", () => {
  it("utilise quatre workers par défaut et accepte une valeur bornée", () => {
    expect(scanConcurrencyLimit(undefined)).toBe(4);
    expect(scanConcurrencyLimit("8")).toBe(8);
  });

  it.each(["0", "33", "1.5", "texte", ""])("rejette la valeur invalide %j", (value) => {
    expect(() => scanConcurrencyLimit(value)).toThrow();
  });
});
