import type { Finding, FindingStatus } from "./types";

const statusOrder: Record<FindingStatus, number> = { fail: 0, warning: 1, unavailable: 2, pass: 3, not_observed: 4, not_applicable: 5 };

export function prioritizeFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const statusDifference = statusOrder[left.status] - statusOrder[right.status];
    if (statusDifference !== 0) return statusDifference;
    return (right.maxPoints - right.points) - (left.maxPoints - left.points);
  });
}

export function remediationPriorities(findings: Finding[], limit = 3): Finding[] {
  return prioritizeFindings(findings).filter(({ status }) => status === "fail" || status === "warning").slice(0, Math.max(0, limit));
}

export function findingSummary(findings: Finding[]) {
  return findings.reduce((summary, finding) => {
    summary[finding.status] += 1;
    return summary;
  }, { pass: 0, warning: 0, fail: 0, not_observed: 0, not_applicable: 0, unavailable: 0 });
}

export function displayHostname(value: string): string {
  try { return new URL(value).hostname; } catch { return "Site analysé"; }
}

export function isEvaluatedFinding(finding: Finding): boolean {
  return ["pass", "warning", "fail"].includes(finding.status);
}

export const findingStatusLabels: Record<FindingStatus, string> = {
  pass: "Réussi", warning: "À améliorer", fail: "À corriger",
  not_observed: "Non observé", not_applicable: "Non applicable", unavailable: "Non vérifiable",
};
