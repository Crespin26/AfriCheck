import { expect, test, type Page } from "@playwright/test";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";

// Network diagnostics are simulated: these tests never scan a third-party site.
const diagnostic = {
  url: "https://example.com/",
  finalUrl: "https://example.com/",
  scannedAt: "2026-10-19T10:00:00.000Z",
  durationMs: 250,
  score: 75,
  grade: "B",
  findings: [{
    id: "https", title: "Connexion HTTPS", status: "pass", points: 15,
    maxPoints: 15, observation: "La page utilise HTTPS.",
    recommendation: "Conservez le renouvellement automatique.",
  }, {
    id: "hsts", title: "HSTS", status: "fail", points: 0,
    maxPoints: 5, observation: "HSTS absent.",
    recommendation: "Activez HSTS sur le serveur.",
  }],
};

function signedDiagnostic() {
  const expiresAt = Date.now() + 3_600_000;
  const report = {
    finalUrl: diagnostic.finalUrl, scannedAt: diagnostic.scannedAt,
    durationMs: diagnostic.durationMs, score: diagnostic.score,
    grade: diagnostic.grade, findings: diagnostic.findings,
  };
  const signature = createHmac("sha256", "playwright-report-signing-key-at-least-32")
    .update(JSON.stringify(["africheck-report-v1", expiresAt, report])).digest("base64url");
  return { ...diagnostic, reportAuthorization: { expiresAt, signature } };
}

async function submit(page: Page) {
  await page.getByLabel("Adresse du site à analyser").fill("example.com");
  await page.getByRole("button", { name: "Analyser mon site" }).click();
}

test("affiche le diagnostic, ses recommandations et télécharge un vrai PDF", async ({ page }) => {
  await page.route("**/api/scan", (route) => route.fulfill({ json: signedDiagnostic() }));
  await page.goto("/");
  await submit(page);
  await expect(page.getByRole("heading", { name: "Bonne base de sécurité" })).toBeVisible();
  await expect(page.getByText("Activez HSTS sur le serveur.").first()).toBeVisible();
  await page.locator("summary").filter({ hasText: "Connexion HTTPS" }).click();
  await expect(page.getByText("La page utilise HTTPS.")).toBeVisible();
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Télécharger le rapport PDF" }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("africheck-example.com-2026-10-19.pdf");
  const file = await download.path();
  expect(file).not.toBeNull();
  expect((await readFile(file!)).subarray(0, 5).toString()).toBe("%PDF-");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("affiche le refus réel d’une cible réseau privée", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Adresse du site à analyser").fill("http://127.0.0.1");
  await page.getByRole("button", { name: "Analyser mon site" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Cette adresse réseau" })).toHaveText("Cette adresse réseau n’est pas autorisée.");
  await expect(page.getByRole("button", { name: "Analyser mon site" })).toBeEnabled();
});

test("conserve la preuve du domaine et la transmet au diagnostic suivant", async ({ page }) => {
  const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
  const proof = { hostname: "example.com", proof: "test-proof", expiresAt };
  let verifiedSecret = "";
  let ownership: unknown;
  await page.route("**/api/scan", async (route) => {
    ownership = route.request().postDataJSON().ownership;
    await route.fulfill({ json: signedDiagnostic() });
  });
  await page.route("**/api/domains/challenge", async (route) => {
    const body = route.request().postDataJSON();
    expect(body.subject).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(body.clientSecret).toBeUndefined();
    await route.fulfill({ status: 201, json: {
      challenge: "test-challenge", hostname: "example.com", expiresAt,
      verificationUrl: "https://example.com/.well-known/africheck-verification.txt",
    } });
  });
  await page.route("**/api/domains/verify", async (route) => {
    const body = route.request().postDataJSON();
    expect(body.challenge).toBe("test-challenge");
    expect(body.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    verifiedSecret = body.clientSecret;
    await route.fulfill({ json: proof });
  });
  await page.route("**/api/domains/proof", (route) => route.fulfill({ json: { valid: true, hostname: "example.com" } }));
  await page.route("**/api/domains/history", (route) => route.fulfill({ json: { history: [] } }));
  await page.goto("/");
  await submit(page);
  await page.getByRole("button", { name: "Vérifier ce domaine" }).click();
  await expect(page.getByText("https://example.com/.well-known/africheck-verification.txt")).toBeVisible();
  await page.getByRole("button", { name: "J’ai publié le fichier" }).click();
  await expect(page.getByText("Domaine vérifié", { exact: true })).toBeVisible();
  await page.reload();
  await submit(page);
  await expect(page.getByText("Domaine vérifié", { exact: true })).toBeVisible();
  expect(ownership).toEqual({ proof: proof.proof, clientSecret: verifiedSecret });
});


test("refuse réellement un export dont le score a été modifié", async ({ request }) => {
  const result = signedDiagnostic();
  const response = await request.post("/api/report", { data: { ...result, score: 100 } });
  expect(response.status()).toBe(403);
  expect(await response.json()).toMatchObject({ code: "REPORT_UNAUTHORIZED" });
});
