# Certificats réservés aux tests locaux

Ces fichiers publics de test ne doivent jamais être utilisés pour déployer AfriCheck.

- `ca.pem` : autorité locale de test, valide de 2020 à 2040.
- `server-key.pem` : clé publique au dépôt, uniquement pour les serveurs de test `public.example`.
- `valid.pem` : certificat `public.example` signé par cette autorité, valide de 2020 à 2040.
- `expired.pem` : certificat de même nom, expiré depuis le 1er janvier 2021.

La clé privée de l’autorité n’est pas nécessaire aux tests et n’est pas conservée dans le dépôt. Les tests n’approuvent cette autorité que dans leur client HTTPS local ; la configuration TLS de production est inchangée.
