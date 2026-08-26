import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AfriCheck — Diagnostic de sécurité web",
  description: "Analysez gratuitement les protections visibles de votre site et obtenez des recommandations claires.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
