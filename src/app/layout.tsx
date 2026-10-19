import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AfriCheck — Diagnostic de sécurité web",
  description: "Analysez gratuitement les protections visibles de votre site et obtenez des recommandations claires.",
};

/**
 * Définit le document HTML commun, la langue française et l’emplacement du contenu des pages.
 */
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
