"use client";

import { FormEvent, useState } from "react";
import type { ScanResult } from "@/lib/types";
import { displayHostname, findingSummary, prioritizeFindings, remediationPriorities } from "@/lib/report";
import { DomainVerification } from "./domain-verification";
import { createBrowserIdentity, readOwnershipProof } from "@/lib/browser-domain-identity";
import styles from "./scan-form.module.css";

type ScanWithHistory = ScanResult & { history?: { saved: boolean; id?: string; code?: "HISTORY_DISABLED" | "HISTORY_UNAVAILABLE" | "DOMAIN_MISMATCH" } };

async function storedOwnership(input: string): Promise<{ proof: string; clientSecret: string } | undefined> {
  try {
    const candidate = /^[a-z][a-z\d+.-]*:/i.test(input.trim()) ? input.trim() : `https://${input.trim()}`;
    const hostname = new URL(candidate).hostname;
    const proof = readOwnershipProof(window.localStorage, hostname);
    if (!proof) return undefined;
    const identity = await createBrowserIdentity(window.localStorage, window.crypto);
    return { proof: proof.proof, clientSecret: identity.secret };
  } catch { return undefined; }
}

export function ScanForm() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<ScanWithHistory | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setLoading(true); setError(""); setResult(null);
    try {
      const ownership = await storedOwnership(url);
      const response = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url, ...(ownership ? { ownership } : {}) }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? "Le diagnostic a échoué.");
      setResult(data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Le diagnostic a échoué."); }
    finally { setLoading(false); }
  }

  async function exportReport() {
    if (!result) return;
    setExporting(true); setError("");
    try {
      const response = await fetch("/api/report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(result) });
      if (!response.ok) { const data = await response.json(); throw new Error(data.error ?? "L’export du rapport a échoué."); }
      const blobUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = response.headers.get("content-disposition")?.match(/filename="([^"]+)"/)?.[1] ?? "rapport-africheck.pdf";
      link.click();
      URL.revokeObjectURL(blobUrl);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "L’export du rapport a échoué."); }
    finally { setExporting(false); }
  }

  const summary = result ? findingSummary(result.findings) : null;
  const priorities = result ? remediationPriorities(result.findings) : [];
  const orderedFindings = result ? prioritizeFindings(result.findings) : [];

  return (
    <div className={styles.wrap}>
      <form className={styles.form} onSubmit={submit}>
        <span className={styles.lock} aria-hidden>⌁</span>
        <label htmlFor="website" className={styles.srOnly}>Adresse du site à analyser</label>
        <input id="website" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="exemple.bj" inputMode="url" autoComplete="url" required />
        <button disabled={loading}>{loading ? "Analyse…" : "Analyser mon site"}<span aria-hidden>→</span></button>
      </form>
      {error && <p className={styles.error} role="alert">{error}</p>}
      {result && (
        <section className={styles.result} aria-live="polite">
          <div className={styles.score}><strong>{result.score}</strong><span>/100</span><small>Note {result.grade}</small></div>
          <div className={styles.summary}>
            <p>{displayHostname(result.finalUrl)} · Diagnostic terminé en {(result.durationMs / 1000).toFixed(1)} s</p>
            <h2>{result.score >= 75 ? "Bonne base de sécurité" : result.score >= 50 ? "Des améliorations sont nécessaires" : "Plusieurs protections sont à renforcer"}</h2>
            <div className={styles.counts} aria-label="Résumé des contrôles">
              <span data-status="fail"><b>{summary?.fail}</b> à corriger</span>
              <span data-status="warning"><b>{summary?.warning}</b> à améliorer</span>
              <span data-status="pass"><b>{summary?.pass}</b> réussi{summary?.pass === 1 ? "" : "s"}</span>
            </div>
            {priorities.length > 0 && <div className={styles.priorities}>
              <h3>Actions prioritaires</h3>
              <ol>{priorities.map((finding) => <li key={finding.id}><b>{finding.title}</b><span>{finding.recommendation}</span></li>)}</ol>
            </div>}
            <div className={styles.findings}>
              <h3>Résultats détaillés</h3>
              {orderedFindings.map((finding) => <details key={finding.id} data-status={finding.status}>
                <summary><span>{finding.status === "pass" ? "✓" : finding.status === "fail" ? "×" : "!"}</span><b>{finding.title}</b><em>{finding.points}/{finding.maxPoints}</em></summary>
                <div><p>{finding.observation}</p><strong>Recommandation</strong><p>{finding.recommendation}</p></div>
              </details>)}
            </div>
            <button type="button" className={styles.exportButton} onClick={exportReport} disabled={exporting}>{exporting ? "Création du PDF…" : "Télécharger le rapport PDF"}<span aria-hidden>↓</span></button>
            {result.history?.saved && <p className={styles.historySuccess} role="status">✓ Diagnostic ajouté à l’historique sécurisé.</p>}
            {result.history && !result.history.saved && <p className={styles.historyWarning} role="status">Le diagnostic est terminé, mais l’historique n’a pas pu être mis à jour.</p>}
            <DomainVerification key={result.finalUrl} targetUrl={result.finalUrl} />
          </div>
        </section>
      )}
    </div>
  );
}
