/**
 * Distingue un dépassement de taille d’un corps JSON ou UTF-8 invalide.
 */
export class RequestBodyError extends Error {
  constructor(readonly code: "TOO_LARGE" | "INVALID_JSON") {
    super(code);
    this.name = "RequestBodyError";
  }
}

/**
 * Lit un JSON UTF-8 en bornant la taille annoncée et les octets réellement reçus.
 * Le type générique ne valide pas la structure métier : chaque route doit vérifier les champs attendus.
 */
export async function readJsonBody<T>(
  request: Request,
  maxBytes: number,
): Promise<T> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const declaredSize = Number(contentLength);
    if (
      !Number.isSafeInteger(declaredSize) ||
      declaredSize < 0 ||
      declaredSize > maxBytes
    ) {
      throw new RequestBodyError("TOO_LARGE");
    }
  }

  const reader = request.body?.getReader();
  if (!reader) throw new RequestBodyError("INVALID_JSON");

  const decoder = new TextDecoder("utf-8", { fatal: true });
  let raw = "";
  let receivedBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      receivedBytes += value.byteLength;
      if (receivedBytes > maxBytes) {
        await reader.cancel();
        throw new RequestBodyError("TOO_LARGE");
      }
      raw += decoder.decode(value, { stream: true });
    }
    raw += decoder.decode();
    return JSON.parse(raw) as T;
  } catch (error) {
    if (error instanceof RequestBodyError) throw error;
    throw new RequestBodyError("INVALID_JSON");
  } finally {
    reader.releaseLock();
  }

}
