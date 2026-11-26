# Vérificateur des preuves Frisk

Outil indépendant pour vérifier les **preuves signées** des versions du document unique (DUERP)
produites par [Frisk Plateforme](https://www.frisk-prevention.fr/plateforme).

Quand une entreprise fige une version de son document unique dans Frisk Plateforme, Frisk signe cette
version. La preuve permet ensuite à quiconque (inspection du travail, expert, assureur, juge, ou
l'entreprise elle-même) de contrôler que la version **n'a pas été modifiée** depuis, **sans dépendre
de Frisk** : ce dépôt contient tout le code nécessaire, et il est public pour pouvoir être relu.

## Ce qu'il faut

1. **Node.js 24 ou plus récent** ([nodejs.org](https://nodejs.org)). Aucune autre installation :
   l'outil n'utilise que le module de chiffrement intégré à Node.js.
2. **L'archive de la preuve** : dans Frisk Plateforme, bouton « 🔏 Preuve » d'une version figée. Elle
   contient `preuve.json` (la preuve signée), `instantane.json` (le contenu figé de la version) et
   `entree.json` (son entrée au registre des versions).
3. **La liste des clés de Frisk** : [`cles-preuve-frisk.json`](cles-preuve-frisk.json) dans ce dépôt.
   Elle est aussi publiée sur [www.frisk-prevention.fr/verification-preuves](https://www.frisk-prevention.fr/verification-preuves)
   ([version JSON](https://www.frisk-prevention.fr/cles-preuve-frisk.json)). La liste n'est jamais dans
   l'archive, pour qu'une archive modifiée ne puisse pas apporter sa propre clé.

## Faire confiance à la liste des clés

Une signature valide prouve seulement que la preuve a été signée avec la clé privée qui correspond à la
clé publique fournie. Elle ne prouve pas, à elle seule, que cette clé appartient à Frisk : c'est la
liste des clés qui l'établit. Avant de vous y fier :

- comparez la liste de ce dépôt et celle du site officiel ; **si elles diffèrent, ne considérez aucune
  clé comme approuvée** et contactez Frisk ;
- comparez son empreinte SHA-256 avec celle publiée ici et dans les versions publiées du dépôt
  (*Releases*) :

  ```
  7583c29ee01ad9b538cee30e986d09e5c9f07d167a37cd3fdd5ddab386278c37  cles-preuve-frisk.json
  ```

  (sous Windows : `certutil -hashfile cles-preuve-frisk.json SHA256` ; sous macOS et Linux :
  `shasum -a 256 cles-preuve-frisk.json`) ;
- gardez une copie de la liste et de son empreinte au moment où vous recevez une preuve : si le site et
  ce dépôt étaient un jour compromis en même temps, deux copies identiques ne suffiraient plus.

## Vérifier une preuve

Téléchargez ce dépôt (bouton *Code* > *Download ZIP*, puis décompressez), placez les fichiers de
l'archive dans le même dossier, puis lancez :

```
node verifier-preuve.mts preuve.json cles-preuve-frisk.json --instantane instantane.json --entree entree.json
```

Option : `--pdf <fichier.pdf>` si la preuve porte aussi sur un PDF.

Le compte rendu dit ce qui a été vérifié et ce qui ne l'a pas été. Résultats possibles :

| Résultat | Signification |
| --- | --- |
| **Conforme** | Signature valide par une clé de Frisk en service à la date de la preuve, et contenu identique à celui signé |
| **Non conforme** | Signature invalide, ou contenu fourni différent de celui qui a été signé |
| **Clé non approuvée** | Clé absente de la liste, révoquée, ou preuve datée hors de sa période d'utilisation |
| **Vérification impossible** | Fichier incomplet ou mal formé |

Code de sortie : 0 si conforme, 1 sinon, 2 si la commande est mal écrite.

## Ce qu'une preuve démontre, et ce qu'elle ne démontre pas

Un résultat « conforme » établit deux choses, et seulement deux :

1. la signature est valide, avec une clé de la liste ;
2. les éléments **effectivement fournis** (instantané, entrée, PDF) correspondent aux empreintes signées.
   Un élément non fourni n'est pas vérifié : le compte rendu le dit.

Il n'établit pas :

- que le document unique est exact, complet ou juridiquement valable, ni la qualité de l'évaluation des
  risques ;
- que la preuve existait à la date qu'elle indique : cette date est **déclarée par Frisk**, sans
  horodatage par un tiers. La période d'utilisation de la clé est contrôlée d'après cette même date ;
- une signature de l'employeur.

## Format

- Signature **Ed25519** (RFC 8032). Les octets signés sont le préfixe ASCII `FRISK-PREUVE-VERSION-1`,
  un octet nul, puis le texte du **manifeste**, écrit selon **RFC 8785** (JSON Canonicalization Scheme).
- `preuve.json` (format `frisk-preuve-fichier-1`) : `{ "format", "manifeste", "signature" }`, le
  manifeste étant le texte exact qui a été signé, la signature 64 octets en hexadécimal.
- Le manifeste (format `frisk-preuve-version-1`) contient notamment l'entreprise, le numéro de version,
  les dates, les empreintes SHA-256 de l'instantané, de l'entrée du registre et de l'entrée précédente,
  l'éventuel PDF et l'identifiant de la clé, jamais la clé elle-même.
- Liste des clés (format `frisk-cles-preuve-1`) : pour chaque clé, identifiant, algorithme, clé publique
  (hexadécimal), début, fin d'utilisation et révocation éventuelles. Une clé n'est jamais retirée de la
  liste : les anciennes preuves en dépendent ; elle reçoit une date de fin ou une révocation.

Le détail de chaque contrôle est dans [`verificateur.ts`](verificateur.ts), écrit pour être relu.

## Tests

```
npm install
npm test
```

Les tests n'utilisent que des clés créées pour l'occasion. `tests/canonique.ts` est l'écriture RFC 8785
qu'utilise Frisk Plateforme pour enregistrer les versions : les tests vérifient que le vérificateur
écrit exactement pareil. C'est une comparaison entre deux écritures de Frisk, pas une preuve
indépendante de conformité à RFC 8785.

## À propos

Ce dépôt reprend à l'identique le vérificateur de Frisk Plateforme : toute modification de l'un est
reportée dans l'autre, avec les tests des deux côtés, et donne lieu à une nouvelle version publiée
(voir [CHANGELOG.md](CHANGELOG.md)). Signaler une faille : [SECURITY.md](SECURITY.md). Contact :
[www.frisk-prevention.fr/contact](https://www.frisk-prevention.fr/contact).

## Licence

MIT (voir [LICENSE](LICENSE)). Vous pouvez utiliser, copier et intégrer ce vérificateur librement.
