import { ScanForm } from "@/components/scan-form";
import styles from "./page.module.css";

const checks = [
  ["HTTPS & TLS", "Connexion chiffrée et redirections sécurisées"],
  ["En-têtes HTTP", "CSP, HSTS, anti-clickjacking et permissions"],
  ["Cookies", "Attributs Secure, HttpOnly et SameSite"],
  ["Pages & formulaires", "Actions non chiffrées et contenu mixte"],
];

export default function Home() {
  return (
    <main>
      <nav className={styles.nav} aria-label="Navigation principale">
        <a href="#accueil" className={styles.brand} aria-label="AfriCheck, accueil">
          <span className={styles.brandMark}>A</span><span>AfriCheck</span>
        </a>
        <span className={styles.beta}>Bêta publique</span>
      </nav>
      <section id="accueil" className={styles.hero}>
        <div className={styles.eyebrow}><span /> Diagnostic web non intrusif</div>
        <h1>La sécurité de votre site,<br /><em>expliquée simplement.</em></h1>
        <p className={styles.lead}>Entrez votre adresse web. AfriCheck vérifie les protections visibles, hiérarchise les risques et vous indique comment les corriger.</p>
        <ScanForm />
        <p className={styles.reassurance}><span>✓</span> Gratuit <span>✓</span> Sans inscription <span>✓</span> Aucun test offensif</p>
      </section>
      <section className={styles.checks} aria-labelledby="checks-title">
        <div className={styles.sectionHeading}>
          <p>Ce que nous vérifions</p><h2 id="checks-title">Un premier diagnostic en quelques secondes</h2>
        </div>
        <div className={styles.grid}>
          {checks.map(([title, copy], index) => (
            <article key={title} className={styles.card}>
              <span className={styles.cardNumber}>0{index + 1}</span>
              <div className={styles.cardIcon}>{["⌁", "≡", "◉", "↗"][index]}</div>
              <h3>{title}</h3><p>{copy}</p>
            </article>
          ))}
        </div>
      </section>
      <footer className={styles.footer}><span>AfriCheck</span><p>Un indicateur pédagogique, pas un remplacement d’un audit professionnel.</p></footer>
    </main>
  );
}
