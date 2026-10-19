"use client";

import { useEffect, useState } from "react";
import {
  browserStorage,
  createBrowserIdentity,
  readOwnershipProof,
  saveOwnershipProof,
  type StoredOwnershipProof,
} from "@/lib/browser-domain-identity";
import styles from "./domain-verification.module.css";

type Challenge = {
  challenge: string;
  verificationUrl: string;
  hostname: string;
  expiresAt: string;
};
type HistoryItem = {
  id: string;
  scannedAt: string;
  score: number;
  grade: string;
  scoringVersion?: 2;
};
type Phase = "idle" | "creating" | "ready" | "verifying" | "verified";

/**
 * Lit un objet JSON exploitable ou renvoie un objet vide si la réponse est invalide.
 */
async function responseData(
  response: Response,
): Promise<Record<string, unknown>> {
  try {
    const data: unknown = await response.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

/**
 * Extrait le message d’erreur fourni par l’API ou utilise le message de repli.
 */
function errorMessage(data: Record<string, unknown>, fallback: string): string {
  return typeof data.error === "string" ? data.error : fallback;
}

/**
 * Vérifie les champs attendus de la réponse de création du challenge.
 */
function isChallenge(
  data: Record<string, unknown>,
): data is Record<string, unknown> & Challenge {
  return (
    typeof data.challenge === "string" &&
    typeof data.verificationUrl === "string" &&
    typeof data.hostname === "string" &&
    typeof data.expiresAt === "string" &&
    Number.isFinite(Date.parse(data.expiresAt))
  );
}

/**
 * Vérifie les champs attendus de la preuve renvoyée après validation du domaine.
 */
function isProof(
  data: Record<string, unknown>,
): data is Record<string, unknown> & StoredOwnershipProof {
  return (
    typeof data.proof === "string" &&
    typeof data.hostname === "string" &&
    typeof data.expiresAt === "string" &&
    Number.isFinite(Date.parse(data.expiresAt))
  );
}

/**
 * Récupère l’historique autorisé ; une indisponibilité ne remet pas en cause la preuve de propriété.
 */
async function requestHistory(
  proof: string,
  clientSecret: string,
): Promise<HistoryItem[] | undefined> {
  try {
    const response = await fetch("/api/domains/history", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ proof, clientSecret }),
    });
    if (!response.ok) return undefined;
    const data = await responseData(response);
    if (!Array.isArray(data.history)) return undefined;
    return data.history.filter((item): item is HistoryItem =>
      Boolean(
        item &&
        typeof item === "object" &&
        typeof (item as HistoryItem).id === "string" &&
        typeof (item as HistoryItem).scannedAt === "string" &&
        Number.isFinite(Date.parse((item as HistoryItem).scannedAt)) &&
        typeof (item as HistoryItem).score === "number" &&
        typeof (item as HistoryItem).grade === "string",
      ),
    );
  } catch { return undefined; }
}

/**
 * Gère les étapes de preuve de domaine et affiche l’historique après validation par le serveur.
 */
export function DomainVerification({ targetUrl }: { targetUrl: string }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [proof, setProof] = useState<StoredOwnershipProof | null>(null);
  const [persistentIdentity, setPersistentIdentity] = useState(true);
  const [historyNotice, setHistoryNotice] = useState("");
  const [history, setHistory] = useState<HistoryItem[] | null>(null);
  const hostname = (() => {
    try {
      return new URL(targetUrl).hostname;
    } catch {
      return "";
    }
  })();

  // Revalide la preuve locale auprès du serveur avant de rétablir l’état vérifié et de charger l’historique.
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const stored = readOwnershipProof(browserStorage(), hostname);
      if (!stored) return;
      void createBrowserIdentity(browserStorage(), window.crypto)
        .then(async (identity) => {
          const response = await fetch("/api/domains/proof", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              proof: stored.proof,
              clientSecret: identity.secret,
            }),
          });
          const data = await responseData(response);
          if (response.ok && data.valid === true) {
            if (data.hostname === hostname) {
              setProof(stored);
              setPhase("verified");
              const entries = await requestHistory(
                stored.proof,
                identity.secret,
              );
              if (entries) setHistory(entries);
              else setHistoryNotice("L’historique n’est pas disponible sur cette instance.");
            }
          }
        })
        .catch(() => undefined);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [hostname]);

  /**
   * Crée l’identité navigateur puis demande le fichier de challenge à publier sur le site cible.
   */
  async function createChallenge() {
    setPhase("creating");
    setError("");
    setNotice("");
    try {
      const identity = await createBrowserIdentity(
        browserStorage(),
        window.crypto,
      );
      const response = await fetch("/api/domains/challenge", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: targetUrl, subject: identity.subject }),
      });
      const data = await responseData(response);
      if (!response.ok)
        throw new Error(
          errorMessage(data, "Impossible de créer le challenge."),
        );
      if (!isChallenge(data))
        throw new Error("La réponse du service de vérification est invalide.");
      setSecret(identity.secret);
      setPersistentIdentity(identity.persistent);
      setChallenge(data);
      setPhase("ready");
      if (!identity.persistent)
        setNotice(
          "Le stockage local est bloqué : terminez la vérification sans recharger cette page.",
        );
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Impossible de créer le challenge.",
      );
      setPhase("idle");
    }
  }

  /**
   * Copie le challenge dans le presse-papiers et indique si le navigateur refuse cette opération.
   */
  async function copyChallenge() {
    if (!challenge) return;
    try {
      await navigator.clipboard.writeText(challenge.challenge);
      setNotice("Challenge copié dans le presse-papiers.");
    } catch {
      setError(
        "La copie automatique est bloquée. Téléchargez plutôt le fichier.",
      );
    }
  }

  /**
   * Télécharge le fichier texte à publier au chemin de vérification indiqué.
   */
  function downloadChallenge() {
    if (!challenge) return;
    const blobUrl = URL.createObjectURL(
      new Blob([`${challenge.challenge}\n`], {
        type: "text/plain;charset=utf-8",
      }),
    );
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = "africheck-verification.txt";
    link.click();
    URL.revokeObjectURL(blobUrl);
    setNotice(
      "Fichier téléchargé. Publiez-le maintenant à l’adresse indiquée.",
    );
  }

  /**
   * Demande la vérification du fichier publié, conserve la preuve obtenue et charge l’historique disponible.
   */
  async function verify() {
    if (!challenge || !secret) return;
    setPhase("verifying");
    setError("");
    setNotice("");
    try {
      const response = await fetch("/api/domains/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          challenge: challenge.challenge,
          clientSecret: secret,
        }),
      });
      const data = await responseData(response);
      if (!response.ok)
        throw new Error(errorMessage(data, "La vérification a échoué."));
      if (!isProof(data))
        throw new Error("La réponse du service de vérification est invalide.");
      const saved = saveOwnershipProof(browserStorage(), data);
      if (!saved || !persistentIdentity) setNotice("La preuve reste disponible tant que cette page est ouverte. Elle n’a pas pu être conservée sur cet appareil.");
      setProof(data);
      setPhase("verified");
      setChallenge(null);
      setSecret("");
      const entries = await requestHistory(data.proof, secret);
      if (entries) setHistory(entries);
      else setHistoryNotice("L’historique n’est pas disponible sur cette instance.");
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "La vérification a échoué.",
      );
      setPhase("ready");
    }
  }

  if (phase === "verified" && proof)
    return (
      <div className={styles.verifiedWrap}>
        <section className={styles.verified} aria-live="polite">
          <span aria-hidden>✓</span>
          <div>
            <strong>Domaine vérifié</strong>
            <p>
              Contrôle de {proof.hostname} confirmé jusqu’au{" "}
              {new Intl.DateTimeFormat("fr-FR", { dateStyle: "long" }).format(
                new Date(proof.expiresAt),
              )}
              .
            </p>
          </div>
        </section>
        {notice && <p className={styles.notice} role="status">{notice}</p>}
        {historyNotice && <p className={styles.notice} role="status">{historyNotice}</p>}
        {history && (
          <section
            className={styles.history}
            aria-labelledby="scan-history-title"
          >
            <div className={styles.historyHeading}>
              <h3 id="scan-history-title">Évolution de la sécurité</h3>
              <span>
                {history.length} diagnostic{history.length === 1 ? "" : "s"}
              </span>
            </div>
            {history.some((item) => item.scoringVersion !== 2) && <p>Les scores v1 et v2 utilisent des calculs différents et ne sont pas directement comparables.</p>}
            {history.length === 0 ? (
              <p>
                Aucun diagnostic enregistré. Relancez l’analyse pour commencer
                le suivi.
              </p>
            ) : (
              <ol>
                {history.map((item) => (
                  <li key={item.id}>
                    <time dateTime={item.scannedAt}>
                      {new Intl.DateTimeFormat("fr-FR", {
                        dateStyle: "medium",
                      }).format(new Date(item.scannedAt))}
                    </time>
                    <strong>
                      {item.score}
                      <small>/100</small>
                    </strong>
                    <span>Note {item.grade} · v{item.scoringVersion ?? 1}</span>
                  </li>
                ))}
              </ol>
            )}
          </section>
        )}
      </div>
    );

  return (
    <section
      className={styles.panel}
      aria-labelledby="domain-verification-title"
    >
      <div className={styles.heading}>
        <span aria-hidden>◆</span>
        <div>
          <h3 id="domain-verification-title">Ce domaine vous appartient ?</h3>
          <p>Vérifiez-le pour préparer un historique de suivi fiable.</p>
        </div>
      </div>
      {phase === "idle" || phase === "creating" ? (
        <button
          type="button"
          className={styles.primary}
          onClick={createChallenge}
          disabled={phase === "creating"}
        >
          {phase === "creating" ? "Préparation…" : "Vérifier ce domaine"}
        </button>
      ) : null}
      {challenge && (phase === "ready" || phase === "verifying") ? (
        <div className={styles.instructions}>
          <ol>
            <li>
              <span>1</span>
              <div>
                <strong>Téléchargez le fichier de preuve</strong>
                <p>
                  Son contenu est signé et expire à{" "}
                  {new Intl.DateTimeFormat("fr-FR", {
                    hour: "2-digit",
                    minute: "2-digit",
                  }).format(new Date(challenge.expiresAt))}
                  .
                </p>
                <div className={styles.actions}>
                  <button type="button" onClick={downloadChallenge}>
                    Télécharger le fichier
                  </button>
                  <button type="button" onClick={copyChallenge}>
                    Copier le contenu
                  </button>
                </div>
              </div>
            </li>
            <li>
              <span>2</span>
              <div>
                <strong>Publiez-le à cette adresse exacte</strong>
                <code>{challenge.verificationUrl}</code>
              </div>
            </li>
            <li>
              <span>3</span>
              <div>
                <strong>Lancez la vérification</strong>
                <p>
                  Le fichier doit être accessible en HTTPS, avec un certificat
                  valide et sans redirection.
                </p>
              </div>
            </li>
          </ol>
          <button
            type="button"
            className={styles.primary}
            onClick={verify}
            disabled={phase === "verifying"}
          >
            {phase === "verifying" ? "Vérification…" : "J’ai publié le fichier"}
          </button>
        </div>
      ) : null}
      {notice && (
        <p className={styles.notice} role="status">
          {notice}
        </p>
      )}
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
