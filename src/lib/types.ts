export type FindingStatus = "pass" | "warning" | "fail";
export type Finding = { id: string; title: string; status: FindingStatus; points: number; maxPoints: number; observation: string; recommendation: string; };
export type ScanResult = { url: string; finalUrl: string; scannedAt: string; durationMs: number; score: number; grade: "A" | "B" | "C" | "D" | "E"; findings: Finding[]; };
