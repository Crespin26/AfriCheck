export type Release = () => void;

/**
 * Valide le plafond de scans simultanés par processus : quatre par défaut, entre un et trente-deux.
 */
export function scanConcurrencyLimit(value = process.env.SCAN_MAX_CONCURRENCY): number {
  if (value === undefined) return 4;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 32) throw new Error("SCAN_MAX_CONCURRENCY doit être un entier entre 1 et 32.");
  return parsed;
}

/**
 * Limite les scans actifs dans ce processus ; ce plafond n’est pas global entre plusieurs instances.
 */
export class ConcurrencyGate {
  private active = 0;

  constructor(private readonly limit: number) {
    if (!Number.isInteger(limit) || limit < 1) throw new Error("Limite de concurrence invalide.");
  }

  /**
   * Réserve une place ou refuse immédiatement ; la fonction renvoyée libère la place une seule fois.
   */
  tryAcquire(): Release | undefined {
    if (this.active >= this.limit) return undefined;
    this.active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
    };
  }
}
