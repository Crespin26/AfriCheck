export type ErrorCode =
  | "INVALID_URL" | "UNSUPPORTED_PROTOCOL" | "TARGET_BLOCKED"
  | "DNS_TIMEOUT" | "REQUEST_TIMEOUT" | "RESPONSE_TOO_LARGE"
  | "UNSUPPORTED_ENCODING" | "INVALID_REDIRECT" | "TOO_MANY_REDIRECTS"
  | "UPSTREAM_HTTP_ERROR" | "UPSTREAM_UNREACHABLE" | "INTERNAL_ERROR";

export class ScanError extends Error {
  constructor(public readonly code: ErrorCode, message: string, public readonly httpStatus = 422) {
    super(message);
    this.name = "ScanError";
  }
}

export type PublicError = { code: ErrorCode; message: string; status: number };

const publicErrors: Record<ErrorCode, Omit<PublicError, "code">> = {
  INVALID_URL: { message: "Adresse web invalide.", status: 422 },
  UNSUPPORTED_PROTOCOL: { message: "Seules les adresses HTTP et HTTPS sont acceptées.", status: 422 },
  TARGET_BLOCKED: { message: "Cette adresse réseau n’est pas autorisée.", status: 422 },
  DNS_TIMEOUT: { message: "La résolution DNS met trop de temps à répondre.", status: 504 },
  REQUEST_TIMEOUT: { message: "Le site met trop de temps à répondre.", status: 504 },
  RESPONSE_TOO_LARGE: { message: "La page est trop volumineuse pour ce diagnostic.", status: 502 },
  UNSUPPORTED_ENCODING: { message: "L’encodage de cette réponse n’est pas pris en charge.", status: 502 },
  INVALID_REDIRECT: { message: "Une redirection non autorisée a été détectée.", status: 422 },
  TOO_MANY_REDIRECTS: { message: "Le site effectue trop de redirections.", status: 502 },
  UPSTREAM_HTTP_ERROR: { message: "Le site a renvoyé une réponse HTTP en erreur.", status: 502 },
  UPSTREAM_UNREACHABLE: { message: "Impossible de joindre ce site pour le moment.", status: 502 },
  INTERNAL_ERROR: { message: "Une erreur interne empêche temporairement le diagnostic.", status: 500 },
};

const errorCodes = new Set<ErrorCode>([
  "INVALID_URL", "UNSUPPORTED_PROTOCOL", "TARGET_BLOCKED", "DNS_TIMEOUT", "REQUEST_TIMEOUT",
  "RESPONSE_TOO_LARGE", "UNSUPPORTED_ENCODING", "INVALID_REDIRECT", "TOO_MANY_REDIRECTS",
  "UPSTREAM_HTTP_ERROR", "UPSTREAM_UNREACHABLE", "INTERNAL_ERROR",
]);

function isKnownScanError(error: unknown): error is ScanError {
  if (!error || typeof error !== "object") return false;
  const candidate = error as Partial<ScanError>;
  return candidate.name === "ScanError" && typeof candidate.code === "string" && errorCodes.has(candidate.code as ErrorCode) &&
    typeof candidate.message === "string" && typeof candidate.httpStatus === "number" && candidate.httpStatus >= 400 && candidate.httpStatus <= 599;
}

export function toPublicError(error: unknown): PublicError {
  if (isKnownScanError(error)) return { code: error.code, ...publicErrors[error.code] };
  const message = error instanceof Error ? error.message : "";
  if (/ENOTFOUND|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|fetch failed/i.test(message)) {
    return { code: "UPSTREAM_UNREACHABLE", ...publicErrors.UPSTREAM_UNREACHABLE };
  }
  return { code: "INTERNAL_ERROR", ...publicErrors.INTERNAL_ERROR };
}
