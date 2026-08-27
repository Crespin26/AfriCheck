import type { Finding, FindingStatus } from "./types";

const statusOrder: Record<FindingStatus, number> = { fail: 0, warning: 1, pass: 2 };

export function prioritizeFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const statusDifference = statusOrder[left.status] - statusOrder[right.status];
    if (statusDifference !== 0) return statusDifference;
    return (right.maxPoints - right.points) - (left.maxPoints - left.points);
  });
}

export function remediationPriorities(findings: Finding[], limit = 3): Finding[] {
  return prioritizeFindings(findings).filter(({ status }) => status !== "pass").slice(0, Math.max(0, limit));
}

export function findingSummary(findings: Finding[]) {
  return findings.reduce((summary, finding) => {
    summary[finding.status] += 1;
    return summary;
  }, { pass: 0, warning: 0, fail: 0 });
}

export function displayHostname(value: string): string {
  try { return new URL(value).hostname; } catch { return "Site analysé"; }
}
