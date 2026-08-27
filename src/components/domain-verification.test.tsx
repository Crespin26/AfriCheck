import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DomainVerification } from "./domain-verification";

describe("DomainVerification", () => {
  it("rend un point d’entrée accessible et compréhensible", () => {
    const markup = renderToStaticMarkup(<DomainVerification targetUrl="https://example.com/" />);
    expect(markup).toContain('aria-labelledby="domain-verification-title"');
    expect(markup).toContain("Ce domaine vous appartient ?");
    expect(markup).toContain("Vérifier ce domaine");
    expect(markup).toContain('type="button"');
  });
});
