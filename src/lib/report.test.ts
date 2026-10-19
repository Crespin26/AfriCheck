import { describe, expect, it } from "vitest";
import type { Finding } from "./types";
import { displayHostname, findingSummary, prioritizeFindings, remediationPriorities } from "./report";

const finding = (id: string, status: Finding["status"], points: number, maxPoints: number): Finding => ({ id, title: id, status, points, maxPoints, observation: "obs", recommendation: "fix" });

describe("report", () => {
  const findings = [finding("pass", "pass", 10, 10), finding("medium", "warning", 4, 5), finding("high", "fail", 0, 15), finding("higher-warning", "warning", 2, 10)];
  it("trie par statut puis par points perdus", () => expect(prioritizeFindings(findings).map(({ id }) => id)).toEqual(["high", "higher-warning", "medium", "pass"]));
  it("exclut les contrôles réussis des priorités", () => expect(remediationPriorities(findings, 2).map(({ id }) => id)).toEqual(["high", "higher-warning"]));
  it("compte chaque niveau", () => expect(findingSummary(findings)).toEqual({ pass: 1, warning: 2, fail: 1, not_observed: 0, not_applicable: 0, unavailable: 0 }));
  it("sépare les états neutres des réussites et des actions de correction", () => {
    const neutral = [finding("absent", "not_observed", 0, 10), finding("unknown", "unavailable", 0, 10), finding("na", "not_applicable", 0, 10)];
    expect(remediationPriorities(neutral)).toEqual([]);
    expect(findingSummary(neutral)).toMatchObject({ pass: 0, not_observed: 1, unavailable: 1, not_applicable: 1 });
  });
  it("affiche uniquement le nom d’hôte", () => {
    expect(displayHostname("https://example.com/private/path?token=secret")).toBe("example.com");
    expect(displayHostname("invalid")).toBe("Site analysé");
  });
});
