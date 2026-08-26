# AfriCheck

AfriCheck est un diagnostic automatisé et non intrusif de la configuration de sécurité visible d’un site web. Il s’adresse en priorité aux PME francophones qui souhaitent comprendre leurs risques sans jargon.

> AfriCheck fournit un indicateur pédagogique. Il ne remplace ni un audit professionnel ni un test d’intrusion autorisé.

## MVP actuel

- normalisation et validation des URL ;
- blocage des adresses privées, locales et des redirections dangereuses ;
- contrôle HTTPS ;
- analyse de HSTS, CSP, X-Content-Type-Options, Referrer-Policy et Permissions-Policy ;
- contrôle anti-clickjacking ;
- inspection des attributs Secure et HttpOnly des cookies de la réponse initiale ;
- détection des formulaires envoyant explicitement des données vers HTTP ;
- score transparent sur 100 et résultat détaillé en français.

Les scans de ports, l’exploitation de vulnérabilités et les affirmations de CVE ne font volontairement pas partie de ce MVP.

## Démarrage local

Prérequis : Node.js 20.9 ou plus récent.

```bash
npm install
npm run dev
```

Ouvrir ensuite [http://localhost:3000](http://localhost:3000).

## Vérifications

```bash
npm run lint
npm run build
```

## Architecture

- `src/app` : interface et route API `POST /api/scan` ;
- `src/components` : formulaire interactif et restitution du score ;
- `src/lib/scanner.ts` : contrôles passifs et calcul du score ;
- `src/lib/url-safety.ts` : validation des cibles et première barrière SSRF.

## Limites connues

Le scanner inspecte la réponse HTTP et le HTML initial. Il ne rend pas encore le JavaScript de la page et ne vérifie pas les parcours authentifiés. Avant une mise en production publique, il faudra ajouter une limitation de débit, une isolation réseau renforcée et une validation du contrôle des domaines pour les analyses avancées.
