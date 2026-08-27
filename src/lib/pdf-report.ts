import "server-only";
import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";
import type { Finding, ScanResult } from "./types";
import { displayHostname, remediationPriorities } from "./report";

const A4 = { width: 595.28, height: 841.89 };
const MARGIN = 48;
const GREEN = rgb(0.031, 0.455, 0.263);
const INK = rgb(0.063, 0.145, 0.102);
const MUTED = rgb(0.376, 0.439, 0.408);
const LINE = rgb(0.886, 0.914, 0.898);
const RED = rgb(0.733, 0.231, 0.231);
const AMBER = rgb(0.733, 0.49, 0.082);

function safeText(value: string): string {
  return value.replace(/[’‘]/g, "'").replace(/[–—‑]/g, "-").replace(/…/g, "...").replace(/[^\x20-\x7E\xA0-\xFF]/g, "?");
}

function wrap(text: string, font: PDFFont, size: number, width: number): string[] {
  const words = safeText(text).split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, size) <= width) line = candidate;
    else {
      if (line) lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  return lines.length ? lines : [""];
}

function drawLines(page: PDFPage, lines: string[], x: number, y: number, font: PDFFont, size: number, color = INK, lineHeight = size * 1.35): number {
  for (const line of lines) { page.drawText(line, { x, y, font, size, color }); y -= lineHeight; }
  return y;
}

export type ReportInput = Pick<ScanResult, "finalUrl" | "scannedAt" | "durationMs" | "score" | "grade" | "findings">;

export function parseReportInput(value: unknown): ReportInput {
  if (!value || typeof value !== "object") throw new Error("Rapport invalide.");
  const input = value as Partial<ReportInput>;
  if (typeof input.finalUrl !== "string" || input.finalUrl.length > 2048) throw new Error("URL du rapport invalide.");
  const parsedUrl = new URL(input.finalUrl);
  if (!["http:", "https:"].includes(parsedUrl.protocol)) throw new Error("URL du rapport invalide.");
  if (typeof input.scannedAt !== "string" || !Number.isFinite(Date.parse(input.scannedAt))) throw new Error("Date du rapport invalide.");
  if (typeof input.durationMs !== "number" || input.durationMs < 0 || input.durationMs > 120_000) throw new Error("Durée du rapport invalide.");
  if (typeof input.score !== "number" || !Number.isInteger(input.score) || input.score < 0 || input.score > 100) throw new Error("Score du rapport invalide.");
  if (!["A", "B", "C", "D", "E"].includes(input.grade ?? "")) throw new Error("Note du rapport invalide.");
  if (!Array.isArray(input.findings) || input.findings.length < 1 || input.findings.length > 30) throw new Error("Constats du rapport invalides.");
  const findings = input.findings.map((item) => parseFinding(item));
  return { finalUrl: parsedUrl.toString(), scannedAt: input.scannedAt, durationMs: input.durationMs, score: input.score, grade: input.grade!, findings };
}

function parseFinding(value: unknown): Finding {
  if (!value || typeof value !== "object") throw new Error("Constat invalide.");
  const item = value as Partial<Finding>;
  const strings = [item.id, item.title, item.observation, item.recommendation];
  if (strings.some((field) => typeof field !== "string" || field.length < 1 || field.length > 700)) throw new Error("Constat invalide.");
  if (!["pass", "warning", "fail"].includes(item.status ?? "")) throw new Error("Statut de constat invalide.");
  if (typeof item.points !== "number" || typeof item.maxPoints !== "number" || item.points < 0 || item.maxPoints < 1 || item.points > item.maxPoints || item.maxPoints > 100) throw new Error("Points de constat invalides.");
  return item as Finding;
}

export async function generateReportPdf(input: ReportInput): Promise<Uint8Array> {
  const document = await PDFDocument.create();
  const regular = await document.embedFont(StandardFonts.Helvetica);
  const bold = await document.embedFont(StandardFonts.HelveticaBold);
  document.setTitle(`AfriCheck - ${displayHostname(input.finalUrl)}`);
  document.setAuthor("AfriCheck");
  document.setSubject("Diagnostic automatise et non intrusif de securite web");
  document.setCreator("AfriCheck");
  document.setCreationDate(new Date(input.scannedAt));

  let page = document.addPage([A4.width, A4.height]);
  let y = drawCover(page, input, regular, bold);
  const priorities = remediationPriorities(input.findings);
  if (priorities.length) {
    y = drawHeading(page, "Actions prioritaires", y, bold);
    for (const [index, finding] of priorities.entries()) {
      const lines = wrap(`${index + 1}. ${finding.title} - ${finding.recommendation}`, regular, 10, A4.width - MARGIN * 2);
      if (y - lines.length * 14 < 90) { page = document.addPage([A4.width, A4.height]); y = drawPageHeader(page, bold); }
      y = drawLines(page, lines, MARGIN, y, regular, 10, INK, 14) - 7;
    }
  }

  y = drawHeading(page, "Resultats detailles", y - 3, bold);
  for (const finding of input.findings) {
    const observation = wrap(finding.observation, regular, 9, A4.width - MARGIN * 2 - 14);
    const recommendation = wrap(`Recommandation : ${finding.recommendation}`, regular, 9, A4.width - MARGIN * 2 - 14);
    const required = 34 + (observation.length + recommendation.length) * 12;
    if (y - required < 76) { page = document.addPage([A4.width, A4.height]); y = drawPageHeader(page, bold); }
    y = drawFinding(page, finding, y, observation, recommendation, regular, bold);
  }

  addFooters(document, regular);
  return document.save();
}

function drawCover(page: PDFPage, input: ReportInput, regular: PDFFont, bold: PDFFont): number {
  page.drawRectangle({ x: 0, y: A4.height - 138, width: A4.width, height: 138, color: GREEN });
  page.drawText("AfriCheck", { x: MARGIN, y: A4.height - 48, font: bold, size: 18, color: rgb(1, 1, 1) });
  page.drawText("RAPPORT DE SECURITE WEB", { x: MARGIN, y: A4.height - 80, font: bold, size: 10, color: rgb(0.79, 0.94, 0.86) });
  page.drawText(safeText(displayHostname(input.finalUrl)), { x: MARGIN, y: A4.height - 110, font: bold, size: 22, color: rgb(1, 1, 1) });
  page.drawRectangle({ x: MARGIN, y: A4.height - 235, width: 116, height: 72, color: rgb(0.91, 0.96, 0.93) });
  page.drawText(String(input.score), { x: MARGIN + 16, y: A4.height - 210, font: bold, size: 36, color: GREEN });
  page.drawText(`/100  Note ${input.grade}`, { x: MARGIN + 64, y: A4.height - 204, font: bold, size: 10, color: GREEN });
  const date = new Intl.DateTimeFormat("fr-FR", { dateStyle: "long", timeStyle: "short", timeZone: "UTC" }).format(new Date(input.scannedAt));
  page.drawText(`Analyse du ${safeText(date)} UTC`, { x: MARGIN + 142, y: A4.height - 188, font: regular, size: 10, color: MUTED });
  page.drawText(`Duree : ${(input.durationMs / 1000).toFixed(1)} s  |  ${input.findings.length} controles`, { x: MARGIN + 142, y: A4.height - 209, font: regular, size: 10, color: MUTED });
  page.drawText("Diagnostic automatise non intrusif. Ce document ne remplace pas un audit ou un test d'intrusion professionnel.", { x: MARGIN, y: A4.height - 260, font: regular, size: 8.5, color: MUTED });
  return A4.height - 300;
}

function drawPageHeader(page: PDFPage, bold: PDFFont): number {
  page.drawText("AfriCheck - Rapport de securite web", { x: MARGIN, y: A4.height - 45, font: bold, size: 10, color: GREEN });
  page.drawLine({ start: { x: MARGIN, y: A4.height - 56 }, end: { x: A4.width - MARGIN, y: A4.height - 56 }, thickness: 1, color: LINE });
  return A4.height - 82;
}

function drawHeading(page: PDFPage, label: string, y: number, bold: PDFFont): number {
  page.drawText(label, { x: MARGIN, y, font: bold, size: 14, color: INK });
  page.drawLine({ start: { x: MARGIN, y: y - 8 }, end: { x: A4.width - MARGIN, y: y - 8 }, thickness: 1, color: LINE });
  return y - 28;
}

function drawFinding(page: PDFPage, finding: Finding, y: number, observation: string[], recommendation: string[], regular: PDFFont, bold: PDFFont): number {
  const color = finding.status === "fail" ? RED : finding.status === "warning" ? AMBER : GREEN;
  const label = finding.status === "fail" ? "A CORRIGER" : finding.status === "warning" ? "A AMELIORER" : "REUSSI";
  page.drawRectangle({ x: MARGIN, y: y - 15, width: 74, height: 18, color });
  page.drawText(label, { x: MARGIN + 7, y: y - 9, font: bold, size: 7, color: rgb(1, 1, 1) });
  page.drawText(safeText(finding.title), { x: MARGIN + 86, y: y - 8, font: bold, size: 10, color: INK });
  page.drawText(`${finding.points}/${finding.maxPoints}`, { x: A4.width - MARGIN - 28, y: y - 8, font: bold, size: 8, color: MUTED });
  y -= 30;
  y = drawLines(page, observation, MARGIN + 7, y, regular, 9, MUTED, 12) - 4;
  y = drawLines(page, recommendation, MARGIN + 7, y, regular, 9, INK, 12) - 12;
  page.drawLine({ start: { x: MARGIN, y: y + 4 }, end: { x: A4.width - MARGIN, y: y + 4 }, thickness: 0.7, color: LINE });
  return y;
}

function addFooters(document: PDFDocument, regular: PDFFont) {
  const pages = document.getPages();
  pages.forEach((page, index) => {
    const pageLabel = `Page ${index + 1}/${pages.length}`;
    page.drawLine({ start: { x: MARGIN, y: 48 }, end: { x: A4.width - MARGIN, y: 48 }, thickness: 0.7, color: LINE });
    page.drawText("africheck - diagnostic pedagogique", { x: MARGIN, y: 31, font: regular, size: 7.5, color: MUTED });
    page.drawText(pageLabel, { x: A4.width - MARGIN - regular.widthOfTextAtSize(pageLabel, 7.5), y: 31, font: regular, size: 7.5, color: MUTED });
  });
}
