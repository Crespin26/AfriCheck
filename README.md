# AfriCheck

AfriCheck est un diagnostic automatisé et non intrusif de la configuration de sécurité visible d’un site web. Il s’adresse en priorité aux PME francophones qui souhaitent comprendre leurs risques sans jargon.

> AfriCheck fournit un indicateur pédagogique. Il ne remplace ni un audit professionnel ni un test d’intrusion autorisé.

## MVP actuel

- normalisation et validation des URL ;
- blocage des adresses privées, locales et des redirections dangereuses ;
- contrôle HTTPS ;
- analyse de HSTS, CSP, X-Content-Type-Options, Referrer-Policy et Permissions-Policy ;
- contrôle anti-clickjacking ;
- inspection du transport, de Secure, HttpOnly, SameSite et des préfixes défensifs des cookies de la réponse initiale ;
- détection des formulaires susceptibles d’envoyer des données sans HTTPS, y compris depuis une page HTTP ;
- inspection du certificat TLS, de sa chaîne et de son expiration ;
- détection du contenu mixte dans le HTML initial ;
- validation de la qualité minimale de HSTS, CSP, Referrer-Policy et des cookies ;
- score transparent sur 100 et résultat détaillé en français.
- détection passive des en-têtes et métadonnées qui exposent une technologie ou sa version ;
- export d’un rapport PDF paginé avec priorités, recommandations et avertissement juridique.

Les scans de ports, l’exploitation de vulnérabilités et les affirmations de CVE ne font volontairement pas partie de ce MVP. Une version exposée est signalée comme une information facilitant le ciblage, jamais comme la preuve automatique d’une vulnérabilité.

## Démarrage local

Prérequis : Node.js 20.9 ou plus récent.

```bash
npm install
npm run dev
```

Ouvrir ensuite [http://localhost:3000](http://localhost:3000).

Pour démarrer la version de production locale :

```bash
npm run build
npm start
```

`npm start` prépare les ressources statiques puis lance le serveur standalone généré. `PORT` et `HOSTNAME` permettent de choisir son port et son interface réseau.

## Vérifications

```bash
npm run lint
npm test
npm run build
# ou toutes les portes de qualité :
npm run ci
```

Pour vérifier les parcours dans Chromium sur ordinateur et en vue mobile :

```bash
npx playwright install chromium
npm run build
npm run test:e2e
```

Ces tests lancent temporairement la version de production sur le port local 3100. Ils vérifient l'affichage du diagnostic, les recommandations, le téléchargement d'un vrai PDF, le refus d'une cible privée et la conservation de la preuve navigateur. Les réponses de scan et de propriété sont simulées ; aucun domaine tiers n'est analysé. Les tests PostgreSQL de `npm test` nécessitent une base dédiée, `DATABASE_URL` exportée et les migrations appliquées ; sans base, ils sont ignorés.

Les mêmes contrôles sont exécutés sur chaque pull request et push vers `main`. CodeQL analyse également le code TypeScript, tandis que Dependabot propose les mises à jour npm, Docker et GitHub Actions. La CI publie un SBOM CycloneDX des dépendances de production et un rapport Trivy de l’image ; toute vulnérabilité HIGH ou CRITICAL disposant d’un correctif bloque la livraison.

## Configuration d’exploitation

- `CLIENT_IP_HEADER=x-forwarded-for|cf-connecting-ip|x-vercel-forwarded-for` : en-tête client unique à utiliser lorsque le proxy est approuvé, `x-forwarded-for` par défaut. Les autres en-têtes fournisseurs sont ignorés. Les adresses invalides partagent une identité de repli et les IPv6 sont normalisées.
- `TRUST_PROXY_HEADERS=true` : active l’identification par adresse transmise uniquement lorsque l’application est placée derrière un proxy de confiance qui remplace ces en-têtes ;
- `LOG_HASH_KEY` : secret aléatoire d’au moins 32 caractères utilisé pour pseudonymiser l’identité réseau dans les journaux. Sans ce secret, aucune empreinte client n’est enregistrée.
- `DOMAIN_VERIFICATION_KEY` : secret aléatoire d’au moins 32 caractères utilisé pour signer les challenges et preuves de contrôle de domaine. Sans ce secret, les endpoints de vérification restent désactivés ; une valeur trop courte fait échouer la readiness.
- `REPORT_SIGNING_KEY` : secret distinct d’au moins 32 octets pour autoriser les exports PDF. Configurez la même valeur sur toutes les instances et conservez-la entre les redémarrages. Sans cette variable, une clé aléatoire propre au processus est utilisée pour les essais locaux ; redémarrer le serveur invalide alors les exports en attente.
- `DATABASE_URL` : URL PostgreSQL dédiée à AfriCheck. Sans cette valeur, les scans restent disponibles mais l’historique est désactivé ;
- `DATABASE_SSL=true|false` : active la validation TLS du serveur PostgreSQL. Utilisez `true` avec un service managé ou un réseau non privé ;
- `HISTORY_RETENTION_DAYS` : conservation des rapports entre 1 et 365 jours, 90 par défaut.
- `SCAN_MAX_CONCURRENCY` : nombre maximal de diagnostics réseau simultanés par instance, entre 1 et 32, 4 par défaut.

Générez les secrets hors du dépôt (par exemple avec un gestionnaire de secrets) et injectez-les à l’exécution. Utilisez des valeurs différentes pour `LOG_HASH_KEY`, `DOMAIN_VERIFICATION_KEY` et `REPORT_SIGNING_KEY`.

### Intégrité des exports PDF

`POST /api/scan` retourne une `reportAuthorization` signée, valable une heure. Le navigateur la retransmet avec le résultat à `POST /api/report`. Le serveur vérifie le domaine, la date, la durée, le score, la note et tous les constats avant de générer le PDF. Un résultat modifié, une autorisation absente ou expirée est refusé avec `403 REPORT_UNAUTHORIZED` ; il faut alors relancer le diagnostic. Les clients API doivent conserver ce champ avec le résultat.

Cette protection garantit que les données acceptées pour l’export proviennent du scanner. Elle n’est pas une signature numérique du fichier PDF téléchargé et ne permet pas de vérifier un fichier modifié après téléchargement.

### Vérification de contrôle d’un domaine

1. Le navigateur génère localement un secret aléatoire de 32 octets et envoie seulement son empreinte SHA-256 base64url à `POST /api/domains/challenge` avec l’URL.
2. L’utilisateur publie le challenge reçu à l’adresse `/.well-known/africheck-verification.txt` de son domaine, via HTTPS avec un certificat valide. Le fichier doit être servi directement à cette adresse, sans redirection.
3. Le navigateur transmet le challenge et son secret à `POST /api/domains/verify`. AfriCheck récupère le fichier avec les protections anti-SSRF du scanner et retourne une preuve signée valable 30 jours.
4. Lors des visites suivantes, l’interface revalide la preuve et le secret auprès de `POST /api/domains/proof` avant d’afficher le domaine comme vérifié.

Ce parcours est disponible directement sous chaque rapport de diagnostic. Si le stockage local est bloqué, la preuve et le secret restent temporairement en mémoire dans la page ouverte ; un rechargement les perd. Une panne de l’historique ne remet pas en cause une vérification réussie. La preuve est liée au secret conservé dans le navigateur : copier le fichier public ou modifier le stockage local ne permet donc pas à un tiers de revendiquer le domaine. Les trois endpoints sont limités en fréquence, n’acceptent que des corps de petite taille et renvoient des réponses non mises en cache.

Seuls les diagnostics lancés avec une preuve valide sont enregistrés. AfriCheck ne stocke dans PostgreSQL ni secret navigateur, ni preuve, ni empreinte réseau. Une redirection vers un autre domaine annule l’enregistrement. L’interface présente les 20 derniers scores non expirés du domaine.

Chaque réponse de l’API expose `X-Request-Id`. Les événements sont écrits en JSON avec la durée, le résultat et un code d’erreur stable, sans URL cible ni adresse IP brute. Les secrets doivent être injectés par la plateforme de déploiement et ne doivent jamais être ajoutés au dépôt.

Lorsque PostgreSQL et `LOG_HASH_KEY` sont configurés, les quotas des endpoints coûteux ou sensibles sont atomiques et partagés entre les instances. Seul un HMAC complet de l’identité client est conservé dans une table non journalisée et à durée limitée ; en cas d’indisponibilité de PostgreSQL, l’application se replie sur un quota local sans interrompre le service.

AfriCheck protège également ses propres pages avec une CSP stricte à nonce unique, ainsi qu’avec HSTS en production, anti-clickjacking, `nosniff`, une politique de référent restrictive et une politique de permissions minimale.

## Déploiement conteneurisé

L’image de production est multi-stage, construite depuis le fichier de verrouillage npm et exécutée par l’utilisateur non privilégié `nextjs`. Le stage final applique les mises à jour de sécurité OpenSSL disponibles, puis retire npm, npx et les gestionnaires de paquets inutiles à l’exécution afin de réduire la surface d’attaque. Elle expose le port 3000 et contient un healthcheck.

```bash
docker build -t africheck .
docker run --rm -p 127.0.0.1:3000:3000 --env-file .env.production africheck
```

Pour une installation autonome avec PostgreSQL, définissez `POSTGRES_PASSWORD`, `DOMAIN_VERIFICATION_KEY`, `REPORT_SIGNING_KEY` et `LOG_HASH_KEY` dans l’environnement, puis lancez `docker compose up --build -d`. La base n’est pas exposée sur l’hôte, le conteneur applicatif retire ses capabilities Linux, utilise un système de fichiers en lecture seule et applique les migrations sous verrou avant de démarrer.

Sur une plateforme gérée, exécutez `npm run db:migrate` comme tâche de déploiement avant de remplacer les instances. Sauvegardez régulièrement PostgreSQL et testez la restauration ; la rétention applicative ne remplace pas une politique de sauvegarde.

### Proxy HTTPS sur un serveur Docker

Le Compose de base publie le port 3000 uniquement sur `127.0.0.1` pour les essais locaux. Sur un serveur compatible Docker avec Compose 2.24.4 ou plus récent, le fichier complémentaire ajoute Caddy et retire entièrement ce port publié : seuls les ports HTTP/HTTPS du proxy sont accessibles. PostgreSQL reste sur un réseau interne auquel le proxy n’est pas connecté.

Après achat du domaine, configurez son DNS vers le serveur, ouvrez les ports 80/TCP, 443/TCP et éventuellement 443/UDP, puis définissez le domaine réel et les quatre secrets persistants déjà décrits :

```bash
# Remplacer ce domaine fictif par le domaine réellement contrôlé.
export AFRICHECK_DOMAIN=africheck.example
export COMPOSE_FILE=compose.yaml:compose.production.yaml
docker compose config --quiet
docker compose up --build -d
docker compose logs --tail=100 proxy app
```

Caddy gère les certificats publics et la redirection HTTP vers HTTPS. Ses données et certificats sont conservés dans des volumes dédiés. Le proxy remplace `X-Forwarded-For` par l’adresse de sa connexion entrante et supprime les en-têtes Cloudflare/Vercel fournis par le client. L’application n’accepte alors que `x-forwarded-for` pour les quotas. Ce montage cible un accès direct au proxy ; ajouter un CDN ou un autre proxy en amont demande une configuration de confiance spécifique.

Gardez `COMPOSE_FILE` défini pour les commandes ultérieures de maintenance et de sauvegarde, afin de conserver la même configuration. Pour redémarrer le proxy après modification du Caddyfile : `docker compose restart proxy`.

Une recette reproductible teste un certificat local avec sa propre autorité explicitement approuvée par le client de test, la redirection HTTPS, l’absence de ports applicatif/PostgreSQL publics, le refus du contournement des quotas par en-têtes falsifiés et la séparation des quotas de deux clients réseau :

```bash
docker build -t africheck:ci .
npm run test:proxy
```

Le test crée un projet Compose isolé sur des ports locaux aléatoires, puis le supprime. Il ne demande aucun certificat public et n’utilise aucun domaine tiers. Il est exécuté en CI. La délivrance du certificat public et l’accessibilité depuis Internet restent à vérifier sur le domaine et l’hébergement définitifs.

Références : [HTTPS automatique Caddy](https://caddyserver.com/docs/automatic-https), [en-têtes du reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) et [fusion des fichiers Compose](https://docs.docker.com/reference/compose-file/merge/).

### Sauvegarde et restauration PostgreSQL

Depuis le dépôt sur l’hôte Docker, avec l’environnement Compose habituel configuré et le service `database` démarré :

```bash
mkdir -p backups
npm run db:backup -- backups/africheck-2026-10-19.dump
npm run db:restore -- backups/africheck-2026-10-19.dump africheck_recovery
```

Choisissez un nom de fichier unique à chaque sauvegarde. Les archives sont créées avec des permissions `0600` et un fichier existant n’est jamais remplacé. Elles contiennent le schéma, les migrations et l’historique ; les compteurs temporaires des quotas sont exclus. Les dossiers `backups/` et les fichiers `.dump` sont exclus de Git et du contexte Docker.

La restauration crée une **nouvelle base** : elle refuse toute destination déjà existante, y compris la base active `africheck`. Elle s’arrête à la première erreur et applique la restauration dans une transaction. Si elle échoue, la nouvelle base reste disponible pour inspection ; le script ne supprime aucune base. Vérifiez ensuite les tables, les rapports et la readiness avec une instance de test pointant sur cette nouvelle base avant de décider d’une bascule. Les secrets applicatifs ne font pas partie de l’archive et doivent être conservés séparément.

Planifiez les sauvegardes sur l’hébergement, conservez une copie chiffrée hors du serveur et définissez leur durée de conservation. Le test reproductible suivant utilise un projet Docker temporaire isolé, puis supprime ses conteneurs :

```bash
npm run test:recovery
```

Il vérifie la restauration des rapports et migrations, l’exclusion des quotas, le refus d’écraser une archive ou une base et le maintien de la base source. Il est également exécuté en CI. Ces scripts ciblent l’installation Docker Compose du dépôt ; pour une base gérée, utilisez les outils de sauvegarde de la plateforme.

Références : [pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html) et [pg_restore](https://www.postgresql.org/docs/17/app-pgrestore.html).

### Nettoyage des données expirées

Pour supprimer les rapports et quotas expirés même lorsqu’aucun nouveau scan n’est lancé, planifiez quotidiennement cette commande sur l’hôte de déploiement :

```bash
docker compose exec -T app node scripts/cleanup.mjs
```

Hors Docker, utilisez `npm run db:cleanup` avec `DATABASE_URL` et `DATABASE_SSL` exportées. La commande ne supprime que les lignes dont `expires_at` est dépassé ; les rapports encore valides sont conservés. Elle peut être relancée sans effet sur les données non expirées. La planification doit être configurée sur la plateforme d’hébergement.

- `GET /api/health` : liveness sans dépendance externe ;
- `GET /api/ready` : readiness du runtime, de la configuration et du schéma PostgreSQL lorsqu’il est activé ;
- ne rendez pas directement le conteneur accessible sur Internet : placez-le derrière un proxy TLS qui remplace les en-têtes client avant d’activer `TRUST_PROXY_HEADERS=true`.

## Architecture

- `src/app` : interface et route API `POST /api/scan` ;
- `src/components` : formulaire interactif et restitution du score ;
- `src/lib/scanner.ts` : contrôles passifs et calcul du score ;
- `src/lib/url-safety.ts` : validation DNS, IPv4 et IPv6 des cibles ;
- `src/lib/transport.ts` : connexion avec adresse IP épinglée, limites et collecte TLS.
- `src/lib/scan-history.ts` : persistance PostgreSQL paramétrée et rétention des diagnostics vérifiés.

Le transport réapplique la validation réseau à chaque redirection, refuse qu’une redirection introduise des identifiants ou change de port, conserve l’adresse DNS validée pendant la connexion, limite à 2 Mo le corps analysé et impose un délai absolu de 12 secondes pour l’ensemble de la navigation, redirections comprises. Une instance n’exécute que quatre diagnostics réseau simultanés par défaut et refuse rapidement la surcharge avec `503` et `Retry-After`. Les réponses compressées inattendues sont refusées afin d’éviter l’analyse de données ambiguës ou une décompression excessive.

## Méthode de diagnostic v2 et recette du scanner

Les nouveaux résultats portent `scoringVersion: 2`. Les statuts distinguent :

| Statut API | Signification | Effet sur le score |
| --- | --- | --- |
| `pass` | Protection ou propriété observée dans le périmètre inspecté | Points prévus par le contrôle |
| `warning` | Configuration à examiner ou à améliorer | Points partiels ou nuls selon le contrôle |
| `fail` | Défaut observé | Aucun point pour ce contrôle |
| `not_observed` | Aucun élément à évaluer : par exemple aucun cookie actif ou formulaire | Exclu du calcul |
| `not_applicable` | Contrôle sans objet : par exemple contenu mixte sur une page HTTP | Exclu du calcul |
| `unavailable` | Informations insuffisantes ou contenu non pris en charge | Exclu du calcul, limite affichée |

Le score est le pourcentage des points obtenus sur les seuls contrôles évalués (`pass`, `warning`, `fail`). Un échec HTTPS ou TLS le plafonne à **49/100**, afin qu’un certificat invalide ou une rétrogradation vers HTTP ne soit pas masqué par de bons en-têtes. L’absence d’un cookie, d’un formulaire ou d’une empreinte ne donne plus de points. Un score élevé ne couvre donc que les contrôles effectivement évalués : le nombre de contrôles évalués et les limites sont affichés dans l’interface et le PDF. Les scores historiques v1 sont conservés et identifiés ; ils ne sont pas directement comparables aux scores v2.

L’analyse HTML utilise un arbre de document : les commentaires, chaînes JavaScript et modèles inactifs ne sont pas interprétés comme des balises. La première balise `base`, les entités HTML, les boutons de soumission associés à un formulaire, les candidats `srcset`, les ressources SVG et le CSS intégré sont pris en compte. Les liens de navigation et canoniques ne sont pas classés comme ressources chargées. Les références HTTP sont signalées comme telles, sans prétendre qu’un navigateur les a effectivement chargées ; une CSP peut les bloquer ou les mettre à niveau.

Les cookies et certificats des redirections observées sont inclus. Les instructions de suppression ne sont pas considérées comme des cookies actifs. L’absence de `HttpOnly` reste un avertissement à interpréter selon la sensibilité du cookie et son besoin d’être lu en JavaScript. Une entrée en HTTPS n’entraîne pas de requête HTTP supplémentaire : le rapport précise que ce point d’entrée n’a pas été testé.

Pour reproduire la recette locale :

```bash
npm run test:scanner
```

Elle fait tourner le scanner et son transport contre des serveurs HTTP/TLS locaux : certificat valide et réellement expiré, redirection HTTP→HTTPS, rétrogradation HTTPS→HTTP, cookies intermédiaires, boucles et redirection vers une cible privée. Seuls le DNS et les ports des noms réservés `public.example` et `other.public.example` sont raccordés aux serveurs de test ; les réponses et les échanges TLS sont réels. Aucun site tiers n’est contacté et aucun contournement des protections réseau n’est ajouté à l’API de production. Des tests de régression couvrent aussi les contenus non HTML, les formulaires absents, les styles et les faux éléments HTML.

Les tests navigateur `npm run test:e2e` vérifient les nouveaux statuts, les exports et le diagnostic partiel sur ordinateur et mobile. Ils conservent un exemple de PDF et une capture dans `test-results/`, ignoré par Git.

Références des parseurs : [parse5](https://parse5.js.org/), [CSSTree](https://github.com/csstree/csstree), [srcset](https://github.com/sindresorhus/srcset).

## Limites connues

Le scanner inspecte la navigation HTTP observée et le HTML initial de la page finale. Les réponses JSON, les types inconnus et XHTML/XML ne permettent pas de valider les contrôles HTML. Pour un contenu non identifié comme document HTML/XHTML, les politiques de page (CSP, anti-clickjacking, référent et permissions) sont également signalées comme non vérifiables plutôt que comme des défauts confirmés. Le contenu des pages dans les iframes, des documents `srcdoc`, des modèles de shadow DOM déclaratif et des fichiers CSS externes n’est pas analysé. Les références CSS nécessitant une résolution de variables ou une syntaxe non interprétable sont signalées comme non vérifiables. Il ne rend pas encore le JavaScript de la page et ne vérifie pas les parcours authentifiés. Avant une mise en production publique à grande échelle, il faudra également renforcer l’isolation réseau des workers d’analyse.
