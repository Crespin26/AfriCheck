import { describe, expect, it } from "vitest";
import { readJsonBody, RequestBodyError } from "./request-body";

describe("readJsonBody", () => {
  it("lit un objet JSON sous la limite", async () => {
    const request = new Request("https://app.test/api", {
      method: "POST",
      body: JSON.stringify({ url: "https://example.com" }),
    });

    await expect(readJsonBody(request, 128)).resolves.toEqual({
      url: "https://example.com",
    });
  });

  it("rejette une taille déclarée invalide avant de lire le flux", async () => {
    const request = new Request("https://app.test/api", {
      method: "POST",
      headers: { "content-length": "inconnue" },
      body: "{}",
    });

    await expect(readJsonBody(request, 128)).rejects.toMatchObject({
      code: "TOO_LARGE",
    });
  });

  it("interrompt un flux dès que la limite réelle est dépassée", async () => {
    let cancelled = false;
    let chunksRead = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        chunksRead += 1;
        controller.enqueue(new Uint8Array(8));
      },
      cancel() {
        cancelled = true;
      },
    });
    const request = new Request("https://app.test/api", {
      method: "POST",
      body,
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    await expect(readJsonBody(request, 10)).rejects.toEqual(
      new RequestBodyError("TOO_LARGE"),
    );
    expect(chunksRead).toBeLessThanOrEqual(3);
    expect(cancelled).toBe(true);
  });

  it("rejette le JSON invalide et l’UTF-8 malformé", async () => {
    const malformedJson = new Request("https://app.test/api", {
      method: "POST",
      body: "{",
    });
    const malformedUtf8 = new Request("https://app.test/api", {
      method: "POST",
      body: new Uint8Array([0xc3, 0x28]),
    });

    await expect(readJsonBody(malformedJson, 128)).rejects.toMatchObject({
      code: "INVALID_JSON",
    });
    await expect(readJsonBody(malformedUtf8, 128)).rejects.toMatchObject({

      code: "INVALID_JSON",
    });
  });
});
