"use client";

import { FormEvent, useState } from "react";
import type { ScanResult } from "@/lib/types";
import styles from "./scan-form.module.css";

export function ScanForm() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setLoading(true); setError(""); setResult(null);
    try {
      const response = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? "Le diagnostic a échoué.");
      setResult(data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Le diagnostic a échoué."); }
    finally { setLoading(false); }
  }

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
            <p>Diagnostic terminé en {(result.durationMs / 1000).toFixed(1)} s</p>
            <h2>{result.score >= 75 ? "Bonne base de sécurité" : result.score >= 50 ? "Des améliorations sont nécessaires" : "Plusieurs protections sont à renforcer"}</h2>
            <ul>{result.findings.map((finding) => <li key={finding.id} data-status={finding.status}><span>{finding.status === "pass" ? "✓" : finding.status === "fail" ? "×" : "!"}</span><div><b>{finding.title}</b><small>{finding.observation}</small></div><em>{finding.points}/{finding.maxPoints}</em></li>)}</ul>
          </div>
        </section>
      )}
    </div>
  );
}
