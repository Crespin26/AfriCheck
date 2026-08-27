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
- inspection du certificat TLS, de sa chaîne et de son expiration ;
- détection du contenu mixte dans le HTML initial ;
- validation de la qualité minimale de HSTS, CSP, Referrer-Policy et des cookies ;
- score transparent sur 100 et résultat détaillé en français.
- export d’un rapport PDF paginé avec priorités, recommandations et avertissement juridique.

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
npm test
npm run build
# ou toutes les portes de qualité :
npm run ci
```

Les mêmes contrôles sont exécutés sur chaque pull request et push vers `main`. CodeQL analyse également le code TypeScript, tandis que Dependabot propose les mises à jour npm et GitHub Actions.

## Configuration d’exploitation

- `TRUST_PROXY_HEADERS=true` : active l’identification par adresse transmise uniquement lorsque l’application est placée derrière un proxy de confiance qui remplace ces en-têtes ;
- `LOG_HASH_KEY` : secret aléatoire d’au moins 32 caractères utilisé pour pseudonymiser l’identité réseau dans les journaux. Sans ce secret, aucune empreinte client n’est enregistrée.
- `DOMAIN_VERIFICATION_KEY` : secret aléatoire d’au moins 32 caractères utilisé pour signer les challenges et preuves de contrôle de domaine. Sans ce secret, les endpoints de vérification restent désactivés ; une valeur trop courte fait échouer la readiness.

Générez les secrets hors du dépôt (par exemple avec un gestionnaire de secrets) et injectez-les à l’exécution. Ne réutilisez pas la même valeur pour `LOG_HASH_KEY` et `DOMAIN_VERIFICATION_KEY`.

### Vérification de contrôle d’un domaine

1. Le navigateur génère localement un secret aléatoire de 32 octets et envoie seulement son empreinte SHA-256 base64url à `POST /api/domains/challenge` avec l’URL.
2. L’utilisateur publie le challenge reçu à l’adresse `/.well-known/africheck-verification.txt` de son domaine.
3. Le navigateur transmet le challenge et son secret à `POST /api/domains/verify`. AfriCheck récupère le fichier avec les protections anti-SSRF du scanner et retourne une preuve signée valable 30 jours.
4. Lors des visites suivantes, l’interface revalide la preuve et le secret auprès de `POST /api/domains/proof` avant d’afficher le domaine comme vérifié.

Ce parcours est disponible directement sous chaque rapport de diagnostic. La preuve est liée au secret conservé dans le navigateur : copier le fichier public ou modifier le stockage local ne permet donc pas à un tiers de revendiquer le domaine. Les trois endpoints sont limités en fréquence, n’acceptent que des corps de petite taille et renvoient des réponses non mises en cache.

Chaque réponse de l’API expose `X-Request-Id`. Les événements sont écrits en JSON avec la durée, le résultat et un code d’erreur stable, sans URL cible ni adresse IP brute. Les secrets doivent être injectés par la plateforme de déploiement et ne doivent jamais être ajoutés au dépôt.

AfriCheck protège également ses propres pages avec une CSP stricte à nonce unique, ainsi qu’avec HSTS en production, anti-clickjacking, `nosniff`, une politique de référent restrictive et une politique de permissions minimale.

## Déploiement conteneurisé

L’image de production est multi-stage, construite depuis le fichier de verrouillage npm et exécutée par l’utilisateur non privilégié `nextjs`. Elle expose le port 3000 et contient un healthcheck.

```bash
docker build -t africheck .
docker run --rm -p 3000:3000 --env-file .env.production africheck
```

- `GET /api/health` : liveness sans dépendance externe ;
- `GET /api/ready` : readiness du runtime et de la configuration ;
- ne rendez pas directement le conteneur accessible sur Internet : placez-le derrière un proxy TLS qui remplace les en-têtes client avant d’activer `TRUST_PROXY_HEADERS=true`.

## Architecture

- `src/app` : interface et route API `POST /api/scan` ;
- `src/components` : formulaire interactif et restitution du score ;
- `src/lib/scanner.ts` : contrôles passifs et calcul du score ;
- `src/lib/url-safety.ts` : validation DNS, IPv4 et IPv6 des cibles ;
- `src/lib/transport.ts` : connexion avec adresse IP épinglée, limites et collecte TLS.

Le transport réapplique la validation réseau à chaque redirection, conserve l’adresse DNS validée pendant la connexion, limite à 2 Mo le corps analysé et impose un délai absolu de 12 secondes par requête. Les réponses compressées inattendues sont refusées afin d’éviter l’analyse de données ambiguës ou une décompression excessive.

## Limites connues

Le scanner inspecte la réponse HTTP et le HTML initial. Il ne rend pas encore le JavaScript de la page et ne vérifie pas les parcours authentifiés. La limitation de débit actuelle est locale à chaque instance ; un stockage distribué sera nécessaire pour un déploiement horizontal. Avant une mise en production publique, il faudra également renforcer l’isolation réseau et valider le contrôle des domaines pour les analyses avancées.
