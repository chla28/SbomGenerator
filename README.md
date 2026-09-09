# sbom_generator

Génère un SBOM (Software Bill of Materials) à partir d'une liste mixte de paquets (RPM, Python, Debian, Java, Go, npm/yarn, Maven, Dart/Flutter), d'archives génériques, ou d'une **image de conteneur** (OCI).

---

## Ce que fait le programme

**Entrée (`--input`)** — trois formes possibles :
1. un fichier texte listant une référence par ligne ;
2. une archive/un paquet unique (traité directement, sans fichier liste) ;
3. un **dossier**, scanné récursivement pour tous les types ci-dessous.

`--input` est optionnel dès lors que `--image` (voir plus bas) est fourni ; les deux sources peuvent aussi être combinées.

| Type | Exemples | Outil requis |
|------|----------|--------------|
| RPM installé | `bash`, `glibc-2.42`, `openssl-libs-3.0` | `rpm` |
| Fichier `.rpm` local | `/tmp/mypkg-1.0-1.el9.x86_64.rpm` | `rpm` |
| Python wheel `.whl` | `/opt/wheels/requests-2.28.0-py3-none-any.whl` | `python3` |
| Python sdist `.tar.gz` / `.tgz` | `/opt/src/Django-4.2.1.tar.gz` | `python3` |
| Archive tar générique `.tar.gz` / `.tgz` | `/opt/3PP/apache-tomcat-10.1.44.tar.gz` | `python3` |
| Archive ZIP générique `.zip` | `/opt/3PP/myapp-2.0.0-linux-amd64.zip` | `python3` |
| Paquet Debian `.deb` | `/opt/pkgs/libssl3_3.0.1_amd64.deb` | `dpkg-deb` |
| Archive Java `.jar` | `/opt/libs/my-lib-1.2.3.jar` | `unzip` |
| Requirements Python `.txt` | `/opt/reqs/requirements.txt` | *(aucun)* |
| Modules Go `go.sum` / `go.mod` | `/opt/myapp/go.sum` | *(aucun)* |
| Paquets npm `package-lock.json` | `/opt/webapp/package-lock.json` (v1/v2/v3) | *(aucun)* |
| Paquets yarn `yarn.lock` | `/opt/webapp/yarn.lock` (classique et Berry) | *(aucun)* |
| Dépendances Maven `pom.xml` | `/opt/javaapp/pom.xml` (scope compile) | *(aucun)* |
| Lockfile Dart/Flutter `pubspec.lock` | `/opt/flutterapp/pubspec.lock` (versions résolues + transitives) | *(aucun)* |
| Manifeste Dart/Flutter `pubspec.yaml` | `/opt/flutterapp/pubspec.yaml` (dépendances directes) | *(aucun)* |

Les lignes commençant par `#` sont ignorées. Les types peuvent être mélangés librement dans un même fichier ou dossier.

**Image de conteneur (`--image` / `-I`)** — alternative ou complément à `--input` :

| Forme | Exemple |
|-------|---------|
| Référence de registre | `nginx:latest`, `ubuntu@sha256:…` |
| Archive tar exportée | `/path/image.tar`, `.tar.gz`, `.tgz` (ex. `docker save`) |
| Répertoire OCI layout | `/path/oci_dir/` (contient `index.json`) |

Backend d'analyse au choix (`--oci-tool`) : `syft` (défaut, tous écosystèmes), `trivy` (tous écosystèmes), `skopeo` (extraction manuelle : dpkg, RPM, APK, Maven JARs, PyPI, npm), ou `cdxgen` (OWASP CycloneDX Generator, tous écosystèmes ; nécessite Node.js).

**Traitement :**
- RPM : 3 appels `rpm` en parallèle par paquet (`--queryformat`, `--requires`, `--provides`)
- Wheel : lecture du fichier `METADATA` embarqué dans le ZIP (via `python3`)
- Archive tar : détection (Python sdist si `PKG-INFO` présent, sinon générique), lecture `LICENSE`/`COPYING`
- Archive ZIP : même logique que tar, via `python3 zipfile`
- Paquet Debian : extraction du fichier `control` via `dpkg-deb -f`, parsing RFC 822
- Archive `.jar` : coordonnées Maven lues via `pom.properties` embarqué, sinon `META-INF/MANIFEST.MF` (Bundle-SymbolicName…), sinon déduites du nom de fichier ; un jar « shaded »/uber-jar embarquant des dépendances relocalisées (chacune avec son propre `pom.properties`) produit un composant par dépendance en plus du jar lui-même
- Requirements.txt : parsing pur Dart (PEP 503), expansion en `WheelPackage` avant la boucle principale
- Go (`go.sum`/`go.mod`), npm (`package-lock.json`), yarn (`yarn.lock`), Maven (`pom.xml`), Dart/Flutter (`pubspec.lock`/`pubspec.yaml`) : parsing pur Dart, expansion en `WheelPackage` avant la boucle principale (même mécanisme que requirements.txt, cardinalité 1 fichier → N paquets)
  - `pubspec.lock` : versions résolues + fermeture transitive complète ; toutes les sources (`hosted`, `git`, `path`, `sdk`). Les dépendances `dependency: "direct dev"` sont exclues (leurs transitives exclusives restent, faute d'information dans le lockfile).
  - Paquets `source: sdk` (`flutter`, `sky_engine`, `flutter_web_plugins`…) : le lockfile les note tous `version: "0.0.0"` (pas de vraie version pour les paquets livrés dans le SDK) — cette version factice est **omise** (`pkg:pub/flutter` sans version). `--sdk-version flutter=3.47.2` injecte la vraie version du SDK (répétable, ex. `--sdk-version dart=3.9.0`) et, en plus, inscrit chaque SDK dans la *toolchain* du SBOM (`metadata.tools.components` en CycloneDX, `creationInfo.creators` en SPDX) — c'est là qu'apparaît la version de `dart`, qui n'a pas de paquet dans le lockfile.
  - **Licences** : `pubspec.lock` n'en contient aucune. Le CLI lit le fichier `LICENSE` de chaque paquet depuis le cache pub (`$PUB_CACHE` ou `~/.pub-cache`, auto-détecté ; `--pub-cache <dir>` pour forcer, `--pub-cache ""` pour désactiver) et pour les paquets `source: sdk` depuis `--flutter-root`. En pratique la licence est renseignée pour la quasi-totalité des dépendances.
  - `pubspec.yaml` : dépendances directes de la section `dependencies:` uniquement (la section `dev_dependencies:` est ignorée) ; version déduite de la contrainte quand elle est univoque (`^1.2.3`, `1.2.3`, `>=1.2.3`), sinon vide.
  - Dans un scan de dossier, si `pubspec.lock` et `pubspec.yaml` coexistent, seul le `.lock` est retenu.
- Image OCI (`--image`) : analyse via `syft`, `trivy`, `skopeo` ou `cdxgen` (`--oci-tool`), en dehors de la boucle concurrente ; combinable avec `--input`
  - `cdxgen` : produit un SBOM CycloneDX complet dont on ne retient que les composants porteurs d'un PURL d'écosystème réel (l'inventaire fichier par fichier de cdxgen et ses actifs cryptographiques sont écartés) ; l'OS de base est reconstitué depuis le qualifiant `distro=` des PURL système
- Dossier : parcours récursif (liens symboliques ignorés) ; seuls les fichiers reconnus par extension/nom exact (`.rpm`, `.deb`, `.whl`, `.jar`, `.zip`, `.tar`/`.tar.gz`/`.tgz`, `requirements.txt`, `pom.xml`, `go.sum`, `go.mod`, `package-lock.json`, `yarn.lock`, `pubspec.lock`, `pubspec.yaml`) sont retenus — un `.txt` quelconque n'est pas traité comme requirements sauf s'il s'appelle exactement `requirements.txt`

**Empreintes cryptographiques :** l'empreinte d'un composant est renseignée
sans requête réseau quand la source la fournit — `integrity` des lockfiles
npm/yarn, `sha256` de `pubspec.lock`, `Digest` Trivy / digests Syft (images
OCI), ou SHA-256+SHA-512 calculés pour un fichier `.rpm`/`.deb`/`.jar`/`.whl`
passé en entrée. Émise en `hashes` (CycloneDX), `checksums` (SPDX 2.3),
`verifiedUsing` (SPDX 3.0). Le hash de l'en-tête RPM est exposé à part
(`rpm:header-sha256`). Souvent absente pour les paquets système d'une image.

**Fournisseur (`supplier`) des composants :** repris de la source quand elle
le porte — `%{VENDOR}` (RPM), `Maintainer:` (Debian), `maintainer`/`Vendor`
(images OCI), `Author-email` (wheels Python), `groupId` (Maven), et, pour
npm, le champ `author` du `package.json` de chaque paquet dans `node_modules`
(absent du lockfile). Les lockfiles Go/pip/pub et `requirements.txt` ne
portent aucun éditeur : `--supplier "<nom>"` fournit une valeur de repli
(sans jamais écraser un fournisseur détecté). En SPDX 2.3, un fournisseur
inconnu est écrit `NOASSERTION` (conforme spéc / NTIA / sbomqs) plutôt
qu'omis.

**Formats de sortie :**

| `-f` | Standard | Contenu |
|------|----------|---------|
| `cyclonedx` | CycloneDX 1.6/1.7 JSON *(1.6 par défaut, `--cyclonedx-version`)* | `components[]` + `dependencies[]` + `compositions[]` |
| `spdx` | SPDX 2.3 JSON | `packages[]` + `relationships[]` |
| `spdx3` | SPDX 3.0 JSON-LD | graphe `@graph` (éléments, relations, organisations) |
| `json` | JSON personnalisé | métadonnées complètes + graphe de dépendances résolu |
| `markdown` | Tableau Markdown | tableau `Paquet / Version / Architecture / Licence` |
| `asciidoc` | Tableau AsciiDoc | idem Markdown, format AsciiDoc |
| `html` | Rapport HTML | rapport autonome filtrable et triable, graphiques par écosystème et licence |
| `csv` | Fichier CSV (RFC 4180) | une ligne par paquet : `name,version,architecture,license,type,purl,url,vendor` |

---

## Installation

### Prérequis

- Dart SDK ≥ 3.0
- `rpm` (pour les paquets RPM)
- `python3` (pour les wheels et archives tar/zip)
- `dpkg-deb` (pour les paquets Debian `.deb`)
- `unzip` (pour les archives `.jar`, et pour `--oci-tool skopeo`)
- `syft`, `trivy`, `skopeo` ou `cdxgen` (uniquement pour `--image`, selon le backend choisi ; `cdxgen` requiert Node.js)
- `grype`, `osv-scanner` ou `trivy` (uniquement pour les sous-commandes `scan` et `cra`)
- accès réseau (uniquement pour l'enrichissement CVE de `scan` / `cra` : CISA KEV, EPSS,
  poc-in-github ; `--no-enrich` ou `SBOMGEN_OFFLINE=1` s'en passe, cache 24 h)
- `asciidoctor-pdf` (uniquement pour `scan`/`cra` `--format pdf` ; sinon le `.adoc` est conservé)
- `sbomqs` (uniquement pour `--min-quality-score`)
- `cosign` (uniquement pour `--sign`)

### Compiler l'exécutable natif

```bash
dart compile exe bin/sbom_generator.dart -o sbom_generator
```

---

## Usage

```
sbom_generator --input <fichier> [options]
sbom_generator --image <image-oci> [options]
sbom_generator --input <fichier> --image <image-oci> [options]
sbom_generator diff <sbom-a> <sbom-b> [--json] [--output <fichier>]
sbom_generator merge <sbom1> <sbom2> ... -o <sortie> [-n <nom>]
sbom_generator convert -i <sbom-source> -f <format> -o <sortie>
sbom_generator validate <sbom1> [<sbom2> ...] [--strict]
sbom_generator scan --sbom <fichier> [options]
sbom_generator cra --sbom <fichier> [options]

Options :
  -i, --input              Fichier d'entrée (requis si --image absent)
  -I, --image              Image de conteneur à analyser : registre, archive
                           tar (.tar/.tar.gz/.tgz) ou répertoire OCI layout
      --oci-tool            Backend d'analyse OCI : syft (défaut) | trivy | skopeo | cdxgen
  -o, --output             Fichier de sortie (défaut : sbom.json)
                           Avec plusieurs formats, utilisé comme base de nom
  -f, --format             Format(s), virgule-séparés :
                             cyclonedx | spdx | spdx3 | json | markdown | asciidoc | html | csv
                           Exemple : -f cyclonedx,spdx,html
  -n, --name               Nom du document SBOM / composant racine
      --supplier           Fournisseur par défaut des composants dont la source
                           ne porte aucun éditeur (n'écrase jamais un fournisseur détecté)
  -d, --rpm-dir            Dossier racine où chercher les fichiers .rpm
                           (résout les noms RPM nus ; ne s'applique pas aux .whl/.tar)
  -c, --concurrency        Nombre de tâches traitées en parallèle (0 = illimité, défaut : 4)
  -l, --license-map        Fichier d'override de licences (une ligne "nom: SPDX-expression")
      --deny-license       Refuser les composants dont la licence correspond au motif
                           (répétable, correspondance SPDX partielle) — code retour 2 si violation
      --sdk-version        Vraie version d'un SDK Dart/Flutter (<sdk>=<version>, répétable) :
                           applique la version aux paquets source: sdk correspondants ET
                           ajoute chaque SDK à metadata.tools (CycloneDX) / creators (SPDX)
      --pub-cache          Cache pub pour lire le LICENSE des paquets d'un pubspec.lock
                           (défaut : $PUB_CACHE puis ~/.pub-cache ; "" pour désactiver)
      --flutter-root       Racine du SDK Flutter, pour le LICENSE des paquets source: sdk
      --min-quality-score  Score sbomqs minimum requis (ex. : 7.5) — code retour 2 si insuffisant
      --sign               Signer les fichiers SBOM avec cosign après génération
      --cyclonedx-version  Version CycloneDX générée : 1.6 (défaut) ou 1.7
      --tlp                Classification TLP du BOM (CycloneDX 1.7 uniquement)
      --patent-map         Déclarations de brevets par paquet (CycloneDX 1.7 uniquement)
  -v, --verbose            Afficher les détails
      --version            Afficher la version
  -h, --help               Afficher l'aide
```

### Sous-commandes

```bash
# Comparer deux SBOMs (ajouts, suppressions, mises à jour de version)
sbom_generator diff avant.cdx.json après.cdx.json
sbom_generator diff avant.cdx.json après.cdx.json --json -o diff.json

# Fusionner plusieurs SBOMs en un seul (déduplication par PURL)
sbom_generator merge base.cdx.json extra.cdx.json -o merged.cdx.json
sbom_generator merge a.cdx.json b.cdx.json c.cdx.json -o merged.cdx.json -n "Système complet"

# Convertir un SBOM existant vers un ou plusieurs formats, sans re-scanner
sbom_generator convert -i sbom.cdx.json -f spdx,csv -o rapport

# Valider la structure d'un ou plusieurs SBOM (0 = tous valides, 1 = au moins un invalide)
sbom_generator validate sbom.cdx.json sbom.spdx.json
sbom_generator validate --strict sbom.cdx.json

# Rechercher les vulnérabilités connues d'un SBOM déjà généré (grype/osv/trivy)
sbom_generator scan --sbom sbom.cdx.json
sbom_generator scan --sbom sbom.cdx.json --scanner all --cve-after 2024-01-01

# Chaque CVE est enrichie (CISA KEV, EPSS, PoC public, exploitabilité CVSS) ;
# filtrer / prioriser :
sbom_generator scan --sbom sbom.cdx.json --only-kev --sort risk
sbom_generator scan --sbom sbom.cdx.json --epss-min 0.1
sbom_generator scan --sbom sbom.cdx.json --no-enrich   # hors-ligne (CI)

# Rapport de synthèse inter-scanners (markdown | asciidoc | pdf), avec section
# « Priorisation par risque » et propriétés kev/epss/poc en SARIF
sbom_generator scan --sbom sbom.cdx.json --scanner all -f pdf -o scan-report.pdf

# Rapport de conformité Cyber Resilience Act (UE 2024/2847) — périmètre
# vérifiable automatiquement : complétude du SBOM (BSI TR-03183-2, éléments
# minimaux NTIA), vulnérabilités connues et correctifs, CVE activement
# exploitées (déclencheur notification ENISA sous 24 h, art. 14)
sbom_generator cra --sbom sbom.cdx.json --config cra.yaml -o rapport-cra.pdf
sbom_generator cra --sbom sbom.cdx.json --no-scan --format json   # exit 2 si non conforme
```

### Exemples

```bash
# CycloneDX 1.6 (défaut)
./sbom_generator -i packages.txt -o sbom.cdx.json

# SPDX 2.3
./sbom_generator -i packages.txt -f spdx -o sbom.spdx.json

# SPDX 3.0 JSON-LD
./sbom_generator -i packages.txt -f spdx3 -o sbom.spdx3.jsonld

# JSON personnalisé avec nom de document
./sbom_generator -i packages.txt -f json -n "Mon Application" -o sbom.json -v

# Tableau Markdown des licences
./sbom_generator -i packages.txt -f markdown -o licences.md

# Rapport HTML interactif
./sbom_generator -i packages.txt -f html -n "Mon Application" -o sbom.html

# Générer CycloneDX + SPDX + HTML en une seule passe
./sbom_generator -i packages.txt -f cyclonedx,spdx,html -o sbom

# Rapport CSV
./sbom_generator -i packages.txt -f csv -o rapport.csv

# Analyser une image de conteneur (registre distant, via syft par défaut)
./sbom_generator -I nginx:latest -o nginx.cdx.json

# Analyser une archive tar exportée (docker save), backend trivy
./sbom_generator -I ./ubuntu.tar --oci-tool trivy -f spdx -o ubuntu.spdx.json

# Analyser une image via cdxgen (OWASP CycloneDX Generator)
./sbom_generator -I nginx:latest --oci-tool cdxgen -o nginx.cdx.json

# Combiner une image OCI et une liste de paquets supplémentaires
./sbom_generator -I nginx:latest -i extra_pkgs.txt -o sbom.cdx.json

# Résoudre les noms RPM depuis un dossier local (pas de rpm installé requis)
./sbom_generator -i packages.txt -d /mnt/repo -o sbom.cdx.json

# --input pointant directement vers un dossier : scan récursif de tous les
# types reconnus (.jar, .rpm, .deb, .whl, archives, manifestes…)
./sbom_generator -i /opt/app/libs -o sbom.cdx.json

# --input pointant directement vers un .jar unique
./sbom_generator -i /opt/app/libs/my-lib-1.2.3.jar -o sbom.cdx.json

# --input pointant directement vers un manifeste unique (lockfile Dart/Flutter,
# requirements.txt, go.sum, package-lock.json, pom.xml…)
./sbom_generator -i /opt/flutterapp/pubspec.lock -o sbom.cdx.json

# Idem, en renseignant la vraie version du SDK Flutter (sinon les paquets
# source: sdk sortent sans version)
./sbom_generator -i /opt/flutterapp/pubspec.lock --sdk-version flutter=3.47.2 -o sbom.cdx.json

# Traitement de 8 entrées en parallèle (liste mixte RPM + .deb + .whl + .txt)
./sbom_generator -i packages.txt -c 8 -o sbom.cdx.json

# Désactiver la limite de parallélisme (toutes les entrées simultanées)
./sbom_generator -i packages.txt -c 0 -o sbom.cdx.json

# Override de licences (fichier texte : une ligne "nom: SPDX-expression")
./sbom_generator -i packages.txt -l overrides.txt -o sbom.cdx.json

# Politiques CI/CD : refuser GPL et AGPL, exiger un score sbomqs ≥ 7.0
./sbom_generator -i packages.txt -o sbom.cdx.json \
  --deny-license GPL --deny-license AGPL \
  --min-quality-score 7.0
# Code retour 2 si violation ; 0 si OK

# Signer les SBOMs avec cosign après génération
./sbom_generator -i packages.txt -f cyclonedx,spdx -o sbom --sign

# CycloneDX 1.7 avec classification TLP et déclarations de brevets
./sbom_generator -i packages.txt --cyclonedx-version 1.7 --tlp AMBER \
  --patent-map patents.txt -o sbom.cdx.json

# Comparer deux SBOMs
./sbom_generator diff ancien.cdx.json nouveau.cdx.json
./sbom_generator diff ancien.cdx.json nouveau.cdx.json --json -o diff.json

# Fusionner plusieurs SBOMs
./sbom_generator merge base.cdx.json extra.cdx.json -o merged.cdx.json -n "Système complet"
```

### Exemple de fichier d'override de licences (`overrides.txt`)

```text
# Overrides de licences — format : nom_paquet: SPDX-expression
libssl3: Apache-2.0
mongodb: SSPL-1.0
my-internal-lib: LicenseRef-Proprietary
```

Chaque ligne `nom: expression` remplace la licence détectée automatiquement pour le paquet de ce nom. Les lignes commençant par `#` sont ignorées.

### Exemple de fichier de brevets (`patents.txt`, CycloneDX 1.7 uniquement)

```text
# Déclarations de brevets — format : nom_paquet: numéro|juridiction|statut|type_assertion
openssl: US1234567|US|granted|license
my-internal-lib: US7654321|US|pending|ownership
```

- `juridiction` : code WIPO ST.3 à 2 lettres (`US`, `EP`, `JP`…)
- `statut` : `pending`, `granted`, `revoked`, `expired`, `lapsed`, `withdrawn`, `abandoned`, `suspended`, `reinstated`, `opposed`, `terminated`, `invalidated`, `in-force`
- `type_assertion` : `ownership`, `license`, `third-party-claim`, `standards-inclusion`, `prior-art`, `exclusive-rights`, `non-assertion`, `research-or-evaluation`

Nécessite `--cyclonedx-version 1.7` (le schéma 1.6 n'a pas de champ `patentAssertions`).

### Exemple de fichier d'entrée

```text
# Noms RPM nus — résolus via --rpm-dir ou interrogés dans la base installée
bash
glibc
openssl-libs

# Fichiers RPM locaux (chemin absolu, toujours utilisé directement)
/mnt/repo/mypkg-1.0-1.el9.x86_64.rpm

# Python wheels
/opt/wheels/requests-2.28.0-py3-none-any.whl
/opt/wheels/numpy-1.24.0-cp311-cp311-linux_x86_64.whl

# Python sdist
/opt/src/Django-4.2.1.tar.gz

# Archives tar binaires tierces (Tomcat, MariaDB, MongoDB…)
/opt/3PP/apache-tomcat-10.1.44.tar.gz
/opt/3PP/mariadb-11.4.8-linux-systemd-x86_64.tar.gz
/opt/3PP/mongodb-linux-x86_64-rhel8-8.0.12.tgz

# Archive ZIP générique
/opt/3PP/myapp-2.0.0-linux-amd64.zip

# Paquets Debian
/opt/pkgs/libssl3_3.0.1_amd64.deb

# Requirements Python (les paquets du fichier sont inclus directement)
/opt/reqs/requirements.txt
```

---

## Comportement selon le type d'archive (tar et zip)

| Contenu de l'archive | Résultat |
|----------------------|----------|
| `PKG-INFO` ou `*.dist-info/METADATA` | Python sdist → PURL `pkg:pypi/…`, métadonnées complètes |
| `LICENSE` / `COPYING` / `LICENSE-*` (sans PKG-INFO) | Archive générique → PURL `pkg:generic/…`, licence identifiée depuis le fichier |
| Ni l'un ni l'autre | Archive générique → nom/version déduits du nom de fichier, licence inconnue |

S'applique aux formats `.tar.gz`, `.tgz`, `.tar` et `.zip`. Les archives `.zip` contenant un `METADATA` Python sont traitées comme des sdists Python.

**Extraction du nom/version depuis le nom de fichier** (archives génériques) :

Le premier segment de version (`\d+\.\d+`) délimite le nom. Les suffixes de plateforme connus (`linux`, `x86_64`, `rhel8`, `systemd`, etc.) sont retirés du nom.

```
apache-tomcat-10.1.44.tar.gz           → nom=apache-tomcat    ver=10.1.44  arch=any
mariadb-11.4.8-linux-systemd-x86_64   → nom=mariadb           ver=11.4.8   arch=x86_64
mongodb-linux-x86_64-rhel8-8.0.12     → nom=mongodb           ver=8.0.12   arch=x86_64
mongodb-database-tools-rhel88-x86_64-100.13.0 → nom=mongodb-database-tools  ver=100.13.0
mongosh-2.5.6-linux-x64               → nom=mongosh           ver=2.5.6    arch=x86_64
```

---

## Structure du projet

```
sbom_generator/
├── bin/
│   └── sbom_generator.dart      # Point d'entrée CLI + sous-commandes
│                                #   diff/merge/convert/validate/scan
├── lib/
│   ├── models.dart              # Package, RpmPackage, WheelPackage, DebPackage,
│   │                            #   OciPackage, PackageHash, PackageDependency, generateUuidV4()
│   ├── hash_utils.dart          # Collecte/normalisation des empreintes (SRI, Digest, fichiers)
│   ├── rpm_parser.dart          # Interrogation rpm (3 appels en Future.wait)
│   ├── wheel_parser.dart        # Lecture des .whl (ZIP + RFC 822)
│   ├── tar_parser.dart          # Lecture des .tar/.tar.gz/.tgz
│   ├── zip_parser.dart          # Lecture des .zip génériques
│   ├── deb_parser.dart          # Lecture des .deb (dpkg-deb -f)
│   ├── jar_parser.dart          # Coordonnées Maven d'un .jar (unzip -p pom.properties)
│   ├── requirements_parser.dart # Parsing requirements.txt Python (pur Dart)
│   ├── go_parser.dart           # Parsing go.sum / go.mod (pur Dart)
│   ├── npm_parser.dart          # Parsing package-lock.json v1/v2/v3 (pur Dart)
│   ├── yarn_parser.dart         # Parsing yarn.lock classique et Berry (pur Dart)
│   ├── maven_parser.dart        # Parsing pom.xml (pur Dart, extraction XML légère)
│   ├── pubspec_parser.dart      # Parsing pubspec.lock / pubspec.yaml (pur Dart)
│   ├── oci_parser.dart          # Analyse images OCI (syft / trivy / skopeo / cdxgen)
│   │                            #   skopeo : RPM, dpkg, APK, Maven JARs, PyPI, npm
│   │                            #   cdxgen : SBOM CycloneDX natif, filtré aux PURL réels
│   ├── archive_helpers.dart     # Helpers partagés tar/zip (parseFilename, identifyLicense)
│   ├── license_normalizer.dart  # Normalisation SPDX centralisée (LicenseNormalizer)
│   ├── spdx_license_ids.dart    # Instantané SPDX License List (garde-fou id vs name)
│   ├── sbom_diff.dart           # Comparaison de SBOMs (SbomDiffer)
│   ├── sbom_merger.dart         # Fusion de SBOMs (SbomMerger)
│   ├── sbom_reader.dart         # Relecture d'un SBOM existant (sous-commande convert)
│   ├── scan_report_generator.dart # Rapport de synthèse inter-scanners (scan -f md/adoc/pdf)
│   ├── vuln_enrichment.dart     # Enrichissement CVE : CISA KEV, EPSS, PoC, exploitabilité CVSS
│   ├── cra_report.dart          # Rapport de conformité Cyber Resilience Act (sous-commande cra)
│   ├── policy_checker.dart      # Contrôle de licences et score qualité CI/CD
│   ├── cyclonedx_generator.dart # Format CycloneDX 1.6/1.7 JSON
│   ├── spdx_generator.dart      # Format SPDX 2.3 JSON
│   ├── spdx3_generator.dart     # Format SPDX 3.0 JSON-LD
│   ├── simple_json_generator.dart  # Format JSON personnalisé
│   ├── markdown_generator.dart  # Tableau Markdown des licences
│   ├── asciidoc_generator.dart  # Tableau AsciiDoc des licences
│   ├── html_generator.dart      # Rapport HTML interactif (filtrable, triable)
│   └── csv_generator.dart       # Export CSV (RFC 4180)
├── test/
│   ├── unit/                    # Tests sans sous-processus réel (parseurs, générateurs,
│   │                            #   licences, politiques…) — voir doc/developer.adoc
│   └── integration/             # Tests sur archives/outils réels (@TestOn('posix'))
├── example/
│   └── 3PP/                     # Exemples d'archives tierces
├── doc/
│   ├── developer.adoc           # Documentation développeur détaillée
│   └── usage.adoc               # Guide d'utilisation détaillé
├── pubspec.yaml
└── README.md
```

---

## PURLs générés par type de paquet

| Type | PURL | Exemple |
|------|------|---------|
| RPM | `pkg:rpm/<name>@<ver>?arch=<arch>` | `pkg:rpm/bash@5.1.8-6.el9?arch=x86_64` |
| Python (wheel / sdist / requirements.txt / OCI) | `pkg:pypi/<name>@<ver>` | `pkg:pypi/requests@2.28.2` |
| Archive tar/zip générique | `pkg:generic/<name>@<ver>` | `pkg:generic/apache-tomcat@10.1.44` |
| Paquet Debian | `pkg:deb/<name>@<ver>?arch=<arch>` | `pkg:deb/libssl3@3.0.1?arch=amd64` |
| Java Maven (`.jar` autonome, `pom.xml`, ou OCI via skopeo) | `pkg:maven/<groupId>/<artifactId>@<ver>` | `pkg:maven/org.yaml/snakeyaml@2.0` |
| Go (`go.sum` / `go.mod`) | `pkg:golang/<module>@<ver>` | `pkg:golang/github.com/gorilla/mux@1.8.1` |
| npm / yarn (`package-lock.json`, `yarn.lock`, ou OCI via skopeo) | `pkg:npm/<name>@<ver>` | `pkg:npm/semver@7.5.4` |
| Dart/Flutter (`pubspec.lock` / `pubspec.yaml`) | `pkg:pub/<name>@<ver>` | `pkg:pub/provider@6.1.2` |
| Image de conteneur (`--image`) | PURL fourni par l'outil d'analyse (syft/trivy/cdxgen), ou reconstruit selon l'écosystème détecté | `pkg:apk/alpine/musl@1.2.4-r2` |
