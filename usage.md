# sbom_generator — Guide d'utilisation

Générateur de SBOM (Software Bill of Materials) à partir d'une liste mixte de paquets ou d'une image OCI.
Prend en charge les types d'entrée **RPM**, **Python wheel**, **archives tar/zip**, **paquets Debian**, **archives Java** (`.jar`), **requirements.txt**, **modules Go** (go.sum/go.mod), **paquets npm/yarn** (package-lock.json/yarn.lock), **paquets Maven** (pom.xml) et **images OCI** (via syft, trivy ou skopeo). `--input` accepte aussi un dossier, scanné récursivement pour tous ces types.
Prend en charge les formats de sortie **CycloneDX 1.6/1.7**, **SPDX 2.3**, **SPDX 3.0 JSON-LD**, **JSON personnalisé**, **Markdown**, **AsciiDoc**, **HTML interactif** et **CSV**.

> Une version plus détaillée (AsciiDoc, avec table des matières et davantage
> d'exemples) existe dans `doc/usage.adoc`. Ce fichier reste le guide rapide
> au format Markdown.

---

## Prérequis

| Composant | Version minimale | Requis pour | Rôle |
|-----------|-----------------|-------------|------|
| [Dart SDK](https://dart.dev/get-dart) | 3.0.0 | toujours | Compilation et exécution |
| `rpm` | — | paquets RPM | Interrogation des métadonnées RPM |
| `python3` | 3.6+ | `.whl`, `.tar*`, `.zip` | Extraction des métadonnées depuis les archives |
| `dpkg-deb` | — | `.deb` | Lecture des métadonnées des paquets Debian |
| `unzip` | — | `.jar` (via `--input`), ou `--image` avec `--oci-tool skopeo` | Extraction des coordonnées Maven (`pom.properties`) |
| `syft` | — | `--image` avec `--oci-tool syft` (défaut) | Analyse d'images OCI — tous types de paquets |
| `trivy` | — | `--image` avec `--oci-tool trivy` | Analyse d'images OCI — tous types de paquets |
| `skopeo` + `tar` | — | `--image` avec `--oci-tool skopeo` | Analyse d'images OCI — dpkg, RPM, APK, Maven JARs, Python, npm |
| `grype` / `osv-scanner` / `trivy` | — | sous-commandes `scan` et `cra` | Recherche de vulnérabilités connues sur un SBOM déjà généré |
| accès réseau | — | enrichissement CVE de `scan` / `cra` | CISA KEV, EPSS, poc-in-github (optionnel : `--no-enrich`, cache 24 h) |
| `asciidoctor-pdf` | — | `scan` / `cra` `--format pdf` | Conversion du rapport en PDF (sinon le `.adoc` est conservé) |
| `sbomqs` | — | `--min-quality-score` | Score de qualité du SBOM généré |
| `cosign` | — | `--sign` | Signature cryptographique du SBOM généré |

Vérification :
```bash
dart --version
rpm --version
python3 --version
dpkg-deb --version
unzip --version
syft version      # si --oci-tool syft
trivy --version   # si --oci-tool trivy ou scan --scanner trivy
skopeo --version  # si --oci-tool skopeo
```

---

## Installation

### Option 1 — Exécution directe avec Dart

```bash
cd sbom_generator
dart pub get          # télécharge les dépendances (package args)
dart run bin/sbom_generator.dart --help
```

### Option 2 — Compilation en binaire natif (recommandé)

```bash
dart compile exe bin/sbom_generator.dart -o sbom_generator
./sbom_generator --help
```

Le binaire `sbom_generator` est autonome, aucun SDK Dart requis pour l'exécuter.

---

## Syntaxe

```
sbom_generator -i <fichier> [options]
sbom_generator -I <image-oci> [options]
sbom_generator -i <fichier> -I <image-oci> [options]
sbom_generator diff <sbom-a> <sbom-b> [--json] [--output <fichier>]
sbom_generator merge <sbom1> <sbom2> ... -o <sortie> [-n <nom>]
sbom_generator convert -i <sbom-source> -f <format> -o <sortie>
sbom_generator licenses -i <sbom-source> -o <licences.adoc> [-f asciidoc|markdown|html|csv|json]
sbom_generator validate <sbom1> [<sbom2> ...]
sbom_generator scan --sbom <fichier> [options]
sbom_generator scan --image <image> [--per-layer] [options]
sbom_generator cra --sbom <fichier> [options]
```

### Options (génération de SBOM)

| Option | Raccourci | Défaut | Description |
|--------|-----------|--------|-------------|
| `--input <chemin>` | `-i` | *(requis si pas de `--image`)* | Fichier liste (une référence par ligne), archive/paquet unique, ou dossier scanné récursivement |
| `--image <référence>` | `-I` | *(requis si pas de `--input`)* | Image OCI à analyser : `nginx:latest`, `/path/image.tar`, `/path/image.tar.gz`, `/path/image.tgz`, `/path/oci_dir/` |
| `--binary <fichier>` | `-b` | — | Binaire local à analyser directement (ex. exécutable Go lié statiquement) ; force `--oci-tool syft` |
| `--oci-tool <outil>` | — | `syft` | Backend d'analyse OCI : `syft` (défaut), `trivy`, `skopeo` |
| `--per-layer` | — | — | Avec `--image` : un SBOM par couche de l'image en plus du global (`<base>.layer-NN-<digest12>.<ext>`, delta de la couche) — voir [SBOM par couche](#un-sbom-par-couche-de-limage---per-layer) |
| `--layer-mode <mode>` | — | `metadata` | Méthode de `--per-layer` : `metadata` (couche d'origine indiquée par syft/trivy) ou `rootfs` (réanalyse après chaque couche ; forcé pour `skopeo` et `cdxgen`) |
| `--output <fichier>` | `-o` | `sbom.json` | Fichier SBOM de sortie (chemin de base si multi-format) |
| `--format <fmt>` | `-f` | `cyclonedx` | Format(s) de sortie, virgule-séparés (voir tableau ci-dessous) |
| `--name <nom>` | `-n` | `Package Set` | Nom du composant racine dans le SBOM |
| `--supplier <nom>` | — | — | Fournisseur par défaut des composants dont la source ne porte aucun éditeur (lockfiles npm/yarn/Go/pip/pub). N'écrase jamais un fournisseur détecté |
| `--rpm-dir <dossier>` | `-d` | — | Dossier de recherche récursive de fichiers `.rpm` ; résout les noms nus sans interroger la base installée |
| `--concurrency <N>` | `-c` | `4` | Nombre de paquets traités simultanément (`0` = illimité) |
| `--license-map <fichier>` | `-l` | — | Fichier de substitution de licences (`nom: SPDX-expression` par ligne) |
| `--deny-license <motif>` | — | — | Refuse les composants dont la licence correspond au motif SPDX (correspondance partielle, répétable). Code retour 2 si au moins une violation |
| `--cyclonedx-version <ver>` | — | `1.6` | Version CycloneDX générée : `1.6` ou `1.7`. Requis pour `--tlp` et `--patent-map` |
| `--tlp <classification>` | — | — | Classification TLP (Traffic Light Protocol) du BOM — 1.7 uniquement. Valeurs : `CLEAR`, `GREEN`, `AMBER`, `AMBER_AND_STRICT`, `RED` |
| `--patent-map <fichier>` | — | — | Fichier de déclarations de brevets par paquet — 1.7 uniquement (voir ci-dessous) |
| `--min-quality-score <score>` | — | — | Score sbomqs minimum requis (ex. `7.5`). Lance `sbomqs score` après génération, code retour 2 si insuffisant |
| `--sign` | — | désactivé | Signe les fichiers SBOM avec `cosign sign-blob` après génération. Un fichier `<sbom>.bundle` est créé à côté de chaque fichier signé |
| `--verbose` | `-v` | désactivé | Affiche les détails de progression |
| `--version` | | | Affiche la version et quitte |
| `--help` | `-h` | | Affiche l'aide |

### Formats disponibles

| Valeur | Standard | Version | Extension | Description |
|--------|----------|---------|-----------|-------------|
| `cyclonedx` | CycloneDX | 1.6 ou 1.7 | `.cdx.json` | Format par défaut (1.6). `--cyclonedx-version 1.7` active en plus `citations`, `patentAssertions` et `distributionConstraints` |
| `spdx` | SPDX | 2.3 | `.spdx.json` | JSON SPDX 2.3 avec `packages[]` et `relationships[]` |
| `spdx3` | SPDX | 3.0 | `.spdx3.jsonld` | JSON-LD SPDX 3.0 avec graphe plat d'éléments (`@graph`) |
| `json` | Personnalisé | — | `.custom.json` | JSON lisible incluant toutes les métadonnées brutes |
| `markdown` | — | — | `.md` | Tableau Markdown des paquets et licences |
| `asciidoc` | — | — | `.adoc` | Tableau AsciiDoc des paquets et licences |
| `html` | — | — | `.html` | Rapport HTML autonome (aucune dépendance externe) : statistiques, graphiques par écosystème et licence, tableau filtrable et triable |
| `csv` | — | — | `.csv` | Fichier CSV (RFC 4180), une ligne par paquet : `name`, `version`, `architecture`, `license`, `type`, `purl`, `url`, `vendor` |

En mode multi-format (`-f cyclonedx,spdx,markdown`), `--output` est traité
comme un chemin de base auquel chaque extension est ajoutée.

---

## Format du fichier d'entrée

Un fichier texte, **une référence par ligne**. Les types peuvent être
mélangés librement dans le même fichier.

### Types de références acceptées

| Type | Exemple | Mécanisme |
|------|---------|-----------|
| Nom de paquet RPM installé | `bash` | `rpm -q bash` |
| NEVRA complet | `bash-5.1.8-6.el9.x86_64` | `rpm -q bash-5.1.8-6.el9.x86_64` |
| Fichier `.rpm` local | `/mnt/repo/bash-5.1.8.rpm` | `rpm -qp /mnt/repo/bash-5.1.8.rpm` |
| Wheel Python `.whl` | `/opt/wheels/requests-2.28.0-py3-none-any.whl` | `python3 zipfile` (extraction METADATA) |
| Archive tar `.tar.gz` / `.tgz` / `.tar` | `/opt/src/mariadb-11.4.8.tar.gz` | `python3 tarfile` → PURL `pkg:pypi/…` ou `pkg:generic/…` |
| Archive ZIP `.zip` | `/opt/src/mylib-1.0.zip` | `python3 zipfile` → PURL `pkg:pypi/…` ou `pkg:generic/…` |
| Paquet Debian `.deb` | `/opt/pkgs/libssl3_3.0.1_amd64.deb` | `dpkg-deb -f` |
| Archive Java `.jar` | `/opt/libs/my-lib-1.2.3.jar` | `pom.properties` embarqué, sinon `META-INF/MANIFEST.MF`, sinon nom de fichier ; PURL `pkg:maven/…`. Un jar « shaded »/uber-jar produit un composant par dépendance embarquée, en plus du jar lui-même |
| Fichier `requirements.txt` | `/opt/project/requirements.txt` | Parseur pur Dart (PEP 508 simplifié) |
| Modules Go (`go.sum`) | `/opt/myapp/go.sum` | Parseur pur Dart — extrait module et version ; PURL `pkg:golang/…` |
| Modules Go (`go.mod`) | `/opt/myapp/go.mod` | Parseur pur Dart — extrait des directives `require` ; PURL `pkg:golang/…` |
| Paquets npm (`package-lock.json`) | `/opt/myapp/package-lock.json` | Parseur pur Dart — lockfileVersion 1, 2 et 3 ; PURL `pkg:npm/…` |
| Paquets yarn (`yarn.lock`) | `/opt/myapp/yarn.lock` | Parseur pur Dart — yarn v1 classique et yarn v2+ Berry ; PURL `pkg:npm/…` |
| Dépendances Maven (`pom.xml`) | `/opt/myapp/pom.xml` | Parseur pur Dart — scope compile/provided, hors test et dependencyManagement ; PURL `pkg:maven/…` |

### Règles de syntaxe

- Les lignes vides sont ignorées.
- Les lignes commençant par `#` sont des commentaires et sont ignorées.
- Les paquets identiques (même `bomRef`) sont automatiquement dédupliqués.

### Raccourci : passer directement une archive unique

`--input` accepte aussi directement le chemin d'une archive ou d'un paquet
unique (`.zip`, `.tar`, `.tar.gz`, `.tgz`, `.whl`, `.deb`, `.rpm`, `.jar`),
sans passer par un fichier liste intermédiaire :

```bash
sbom_generator -i /opt/3PP/myapp-2.0.0-linux-amd64.zip -o sbom
sbom_generator -i /opt/libs/my-lib-1.2.3.jar -o sbom
```

Pour tout autre chemin de fichier, `--input` reste interprété comme un
fichier liste (une référence par ligne).

### Raccourci : passer directement un dossier

Si `--input` pointe vers un **dossier**, celui-ci est scanné récursivement
(liens symboliques ignorés) à la recherche de tous les types de fichiers du
tableau ci-dessus : `.rpm`, `.deb`, `.whl`, `.jar`, `.zip`,
`.tar`/`.tar.gz`/`.tgz`, ainsi que les manifestes reconnus par leur nom exact
(`requirements.txt`, `pom.xml`, `go.sum`, `go.mod`, `package-lock.json`,
`yarn.lock`). Un `.txt` qui ne s'appelle pas exactement `requirements.txt`
n'est donc pas retenu, contrairement au fichier liste où n'importe quel
`.txt` (hors `.whl`) est traité comme un fichier de requirements.

```bash
sbom_generator -i /opt/app/libs -o sbom
```

Les noms de paquets RPM nus (ex. `bash`, sans chemin ni extension) ne
peuvent pas être découverts ainsi : ce ne sont pas des fichiers. Utilisez un
fichier liste ou `--rpm-dir` pour ce cas.

### Exemple de fichier d'entrée mixte

```text
# Paquets RPM (noms installés)
bash
glibc
openssl-libs

# Fichiers RPM locaux
/mnt/BaseOS/Packages/curl-7.76.1-14.el9.x86_64.rpm
/mnt/AppStream/Packages/nginx-1.20.1-14.el9.x86_64.rpm

# Wheels Python
/opt/wheels/requests-2.28.0-py3-none-any.whl

# Archives tierces
/opt/src/mariadb-11.4.8-linux-systemd-x86_64.tar.gz

# Paquet Debian
/opt/pkgs/libssl3_3.0.1_amd64.deb

# Dépendances Python
/opt/project/requirements.txt

# Modules Go (au choix : go.sum ou go.mod)
/opt/myapp/go.sum

# Paquets npm / yarn
/opt/webapp/package-lock.json
/opt/webapp/yarn.lock

# Dépendances Maven
/opt/javaapp/pom.xml

# Commenter un paquet temporairement
# systemd
```

### Générer la liste depuis un système installé

```bash
# Tous les paquets RPM installés
rpm -qa > packages.txt

# Paquets d'un groupe spécifique
rpm -qa --queryformat '%{NAME}\n' | grep ^python > python_pkgs.txt

# Fichiers RPM d'un répertoire ISO/dépôt monté
find /mnt/BaseOS/Packages -name '*.rpm' > rpm_files.txt
```

---

## Exemples d'utilisation

### Génération CycloneDX (défaut)

```bash
./sbom_generator -i packages.txt -o sbom.cdx.json
```

### SPDX 2.3 avec nom personnalisé

```bash
./sbom_generator -i packages.txt -f spdx -n "Mon Application" -o sbom.spdx.json
```

### SPDX 3.0 JSON-LD

```bash
./sbom_generator -i packages.txt -f spdx3 -o sbom.spdx3.jsonld
```

### JSON détaillé avec mode verbeux

```bash
./sbom_generator -i packages.txt -f json -n "Système RHEL 9" -o sbom.json -v
```

### Multi-format en un seul passage

```bash
./sbom_generator -i packages.txt -f cyclonedx,spdx,markdown -o sbom
# Génère : sbom.cdx.json + sbom.spdx.json + sbom.md
```

### Traitement parallèle et override de licences

```bash
# 8 paquets en parallèle + substitution de licences
./sbom_generator -i packages.txt -c 8 -l overrides.txt -o sbom.cdx.json
```

### Résolution de noms RPM depuis un dossier local

```bash
# Les noms nus (bash, glibc…) sont résolus dans /mnt/repo au lieu de rpm -q
./sbom_generator -i packages.txt -d /mnt/repo -o sbom.cdx.json
```

### Analyse d'une image OCI (via syft, défaut)

```bash
./sbom_generator -I nginx:latest -f cyclonedx -n "nginx" -o nginx.cdx.json
```

Avec les backends `syft` et `trivy` (pas `skopeo`), le SBOM CycloneDX/SPDX
généré inclut un composant dédié pour l'OS de base de l'image — nécessaire
pour qu'un outil comme Trivy (`trivy sbom`), rescanné plus tard sur ce
fichier, évalue aussi les CVE des paquets système (RPM/DEB/APK), pas
seulement celles des paquets applicatifs. Sans ce composant, ces CVE
seraient silencieusement absentes du résultat.

**À l'inverse**, il est normal qu'un SBOM généré avec le backend `syft`
fasse remonter, une fois passé dans `trivy sbom`, quelques CVE Java en
plus que `trivy image` sur la même image directement — ce n'est pas un
faux positif du SBOM, mais une sous-détection de l'analyseur de jars
intégré à Trivy. Vérifié sur une image RHEL 9.6/Keycloak : 3 CVE HIGH
(`micrometer-core`, `postgresql`) trouvées via le SBOM mais absentes de
`trivy image` en direct. Cause : Trivy identifie un jar Maven via
`pom.properties`, puis `MANIFEST.MF`, puis un lookup SHA-1 dans sa base
`trivy-java-db` (indexée depuis Maven Central) ; des jars rebuilds
internes Red Hat (`.redhat-000xx`) n'ont pas de `pom.properties` et sont
absents de Maven Central, donc Trivy abandonne silencieusement le paquet.
Syft, lui, sait parser le nom de fichier
`<groupId>.<artifactId>-<version>.jar` (convention du packaging Quarkus
« fast-jar » de cette image) et détecte ces paquets là où Trivy échoue.
Voir `doc/usage.adoc` pour le détail.

### Analyse d'une archive tar exportée avec docker save

```bash
./sbom_generator -I ./ubuntu.tar --oci-tool trivy -f spdx -o ubuntu.spdx.json

# Archive compressée (docker save ubuntu | gzip > ubuntu.tar.gz)
./sbom_generator -I ./ubuntu.tar.gz --oci-tool syft -f cyclonedx -o ubuntu.cdx.json
```

### Analyse d'un OCI layout directory via skopeo

```bash
./sbom_generator -I ./oci_layout/ --oci-tool skopeo -o sbom.cdx.json
```

### Analyse d'un binaire lié statiquement (`--binary`)

```bash
./sbom_generator --binary /usr/local/bin/mon-app -o app.cdx.json
```

`--binary <fichier>` est une variante explicite d'`--image <fichier>` : syft
détecte qu'un chemin local existant n'est pas une référence d'image et
l'analyse directement comme fichier. `--binary` **force `--oci-tool syft`**
(seul backend supporté ici) et refuse toute combinaison avec `--oci-tool
trivy|skopeo|cdxgen` ou avec `--image`.

Portée réelle :
- **Go** (lié statiquement ou non) : la liste complète des modules + versions
  est lue depuis les métadonnées `buildinfo` embarquées dans le binaire
  (celles que `go version -m` affiche) — fonctionne même sur un exécutable
  strippé, tant que le build n'a pas explicitement supprimé cette section.
- **Autres binaires** (Rust, C/C++ statiques…) : syft applique un classifieur
  générique qui reconnaît, par empreinte de chaîne de version, un catalogue
  *fixe* de bibliothèques open source connues (OpenSSL, zlib, sqlite,
  busybox…) — pas une extraction arbitraire des dépendances liées.
- Une bibliothèque liée statiquement sans signature reconnue ni métadonnée
  embarquée (C/C++ « fait maison », Rust sans `cargo-auditable`) **ne peut
  pas** être retrouvée après coup — il faudrait tracer les dépendances au
  moment du build.

### Un SBOM par couche de l'image (`--per-layer`)

```bash
./sbom_generator -I ./app.tar --per-layer -f cyclonedx,csv -o out/app
# → out/app.cdx.json                              SBOM global (annoté)
#   out/app.layer-01-74d97c428c51.cdx.json        couche 1 (base)
#   out/app.layer-02-b676b687f0f5.cdx.json        couche 2 …
#   (et les mêmes en .csv)

# Ajouts, modifications et suppressions : réanalyse du rootfs par couche
./sbom_generator -I nginx:latest --per-layer --layer-mode rootfs -o out/nginx
```

Le global est écrit en premier, puis un SBOM par couche **dans chaque format
demandé** (`-f`), à côté de `-o`. Le nom de base est celui de `-o` sans
extension de format ; l'index de couche est sur deux chiffres au moins, pour
que l'ordre alphabétique suive l'ordre des couches.

| Mode (`--layer-mode`) | Principe | Backends | Contenu d'un SBOM de couche |
|---|---|---|---|
| `metadata` *(défaut)* | couche d'origine indiquée par le backend : `Layer.DiffID` de trivy ; pour syft, seconde analyse en `--scope all-layers` et couche la plus basse où le paquet apparaît | `syft`, `trivy` | composants **ajoutés** par la couche |
| `rootfs` | les couches sont appliquées une à une sur un rootfs cumulé (sémantique overlayfs, *whiteouts* compris), le rootfs est réanalysé après chaque couche, le delta est la différence avec l'état précédent | les quatre — seul mode possible avec `skopeo` et `cdxgen` | composants **ajoutés** et **modifiés** (montée de version, licence ou empreinte différente), composants **supprimés** listés à part |

| Point | Comportement |
|---|---|
| SBOM de couche | composant racine `container` : `version` = digest de la couche (`diff_id`), `description` = instruction de build (`history[].created_by`), propriétés `sbom_generator:layer:*` (index, total, digest, mode, compteurs, un `…:removed` par composant supprimé), BOM-Link vers le SBOM global ; chaque composant porte `sbom_generator:layer:change` (`added`/`modified`) et, pour une montée de version, `…:previousVersion` |
| SBOM global | chaque composant de l'image porte `sbom_generator:layer:index`/`:digest` (couche qui l'a introduit) et `…:modifiedBy` (couches qui l'ont modifié) ; le composant racine porte un résumé JSON par couche (`sbom_generator:layers:NNN`) et un BOM-Link vers chaque SBOM de couche |
| SPDX 2.3 / 3.0 | description en commentaire du document, champs de couche en annotation de chaque paquet (`sbom_generator:layer:<clé>=<valeur>`) ; même UUID que CycloneDX dans l'espace de noms du document |
| Markdown / AsciiDoc / HTML | en-tête décrivant la couche (ou les couches), colonne « Couche » (global) ou « Changement » (couche), section des composants supprimés |
| CSV | colonnes `layer`, `layer_modified_by` (global) ou `change`, `previous_version` (couche, avec une ligne `change=removed` par composant supprimé) |
| `--input` combiné | les paquets venus de `--input` ne figurent que dans le SBOM global |
| `--license-map`, `--supplier` | appliqués aussi aux composants des SBOM de couche |
| `--sign` | signe aussi le premier format de chaque SBOM de couche |
| Non pris en charge | `--binary` (un binaire n'a pas de couches) ; `--layer-mode metadata` avec `skopeo`/`cdxgen` |

Le mode `rootfs` coûte une analyse par couche. Les couches sont lues
directement dans une archive `docker save` / `podman save` (docker-archive
ou oci-archive) ou un layout OCI ; une image de registre est d'abord copiée
localement via `skopeo` (qui doit donc être installé), avec repli sur le
stockage local de podman (`containers-storage:`) puis de Docker
(`docker-daemon:`) pour une image construite localement. La fusion des
couches ne suit jamais un lien symbolique : une couche malveillante ne peut
rien écrire hors du répertoire temporaire.

### Combiner image OCI et liste de paquets supplémentaires

```bash
./sbom_generator -I nginx:latest -i extra_pkgs.txt -f cyclonedx,spdx -o sbom
# Génère : sbom.cdx.json + sbom.spdx.json
```

### Rapport HTML interactif

```bash
./sbom_generator -i packages.txt -f html -n "Mon Application" -o sbom.html
# → sbom.html : rapport autonome, aucune dépendance externe
```

### Rapport CSV

```bash
./sbom_generator -i packages.txt -f csv -o rapport.csv
# → rapport.csv : une ligne par paquet, colonnes :
#   name,version,architecture,license,type,purl,url,vendor
```

### Modules Go

```bash
# Depuis go.sum (toutes les dépendances checksum)
echo "/opt/myapp/go.sum" > sources.txt
./sbom_generator -i sources.txt -f cyclonedx -n "MyGoApp" -o sbom.cdx.json

# Depuis go.mod (dépendances directes et indirectes)
echo "/opt/myapp/go.mod" > sources.txt
./sbom_generator -i sources.txt -f cyclonedx -o sbom.cdx.json
```

### Paquets npm / yarn

```bash
# npm package-lock.json (v1, v2 ou v3)
echo "/opt/webapp/package-lock.json" > sources.txt
./sbom_generator -i sources.txt -f spdx -o webapp.spdx.json

# yarn.lock (v1 classique ou v2+ Berry)
echo "/opt/webapp/yarn.lock" > sources.txt
./sbom_generator -i sources.txt -f cyclonedx,csv -o webapp
# → webapp.cdx.json + webapp.csv
```

### Dépendances Maven

```bash
echo "/opt/javaapp/pom.xml" > sources.txt
./sbom_generator -i sources.txt -f cyclonedx -n "MonServiceJava" -o sbom.cdx.json
```

### Pipeline CI/CD avec contrôle de licences et qualité

```bash
# Refuser GPL et AGPL, exiger un score sbomqs ≥ 7.0
./sbom_generator -i packages.txt -f cyclonedx -o sbom.cdx.json \
  --deny-license GPL --deny-license AGPL \
  --min-quality-score 7.0
# Code retour 0 = OK, 2 = violation politique
```

### Signature cosign

```bash
./sbom_generator -i packages.txt -f cyclonedx,spdx -o sbom --sign
# Génère : sbom.cdx.json + sbom.cdx.json.bundle (signature cosign)
#          sbom.spdx.json + sbom.spdx.json.bundle
```

### CycloneDX 1.7 avec classification TLP et déclarations de brevets

```bash
./sbom_generator -i packages.txt --cyclonedx-version 1.7 --tlp AMBER \
  --patent-map patents.txt -o sbom.cdx.json
```

---

## Comparer, fusionner, convertir, valider et analyser des SBOM

### Comparaison de deux SBOM (`diff`)

```bash
# Diff coloré sur le terminal
./sbom_generator diff avant.cdx.json après.cdx.json

# Diff en JSON (pour automatisation)
./sbom_generator diff avant.cdx.json après.cdx.json --json -o diff.json
```

Fonctionne avec CycloneDX, SPDX 2.3 et SPDX 3.0 (JSON-LD) ; les deux fichiers
comparés peuvent être dans des formats différents (chacun est lu selon sa
propre structure). Codes de retour : `0` = aucun changement, `1` = au moins
un changement détecté.

### Fusion de SBOM (`merge`)

```bash
# Fusionner deux SBOM (déduplication par PURL)
./sbom_generator merge base.cdx.json extra.cdx.json -o merged.cdx.json

# Fusionner plusieurs SBOM avec nom de document
./sbom_generator merge a.cdx.json b.cdx.json c.cdx.json \
  -o merged.cdx.json -n "Système complet"
```

Formats supportés en entrée : CycloneDX ou SPDX 2.3 (tous les fichiers dans
le même format). Le format de sortie suit celui du premier fichier fourni.
Le format SPDX 3.0 (JSON-LD) n'est pas pris en charge en entrée pour `merge`.

### Conversion de format (`convert`)

Convertit un fichier SBOM existant vers un ou plusieurs formats sans re-scanner :

```bash
# CycloneDX → SPDX 2.3
./sbom_generator convert -i sbom.cdx.json -f spdx -o sbom.spdx.json

# SPDX → CycloneDX + CSV (formats multiples)
./sbom_generator convert -i sbom.spdx.json -f cyclonedx,csv -o rapport

# Tous les formats en une seule commande
./sbom_generator convert -i sbom.cdx.json -f spdx,spdx3,markdown,csv -o sbom
```

Formats source acceptés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD.

### Rapport de licences (`licenses`)

Génère un rapport de conformité des licences au format AsciiDoc, regroupé par licence plutôt que par paquet :

```bash
./sbom_generator licenses -i sbom.cdx.json -o licences.adoc

./sbom_generator licenses -i sbom.spdx.json -o licences.adoc -n "Mon projet"

# Autres formats : markdown, html (autonome), csv, json
./sbom_generator licenses -i sbom.cdx.json -f html -o licences.html
./sbom_generator licenses -i sbom.cdx.json -f json    # JSON sur la sortie standard
```

Le rapport commence par un résumé (paquets analysés, licences distinctes,
paquets sous licence copyleft fort/faible, paquets sans licence détectée),
suivi d'un avertissement listant les identifiants copyleft détectés (GPL,
AGPL en copyleft fort ; LGPL, MPL, EPL, CDDL, CPL, EUPL en copyleft faible —
détection heuristique par identifiant SPDX, pas une analyse juridique), puis
d'une section par licence avec la liste des paquets concernés. `--format`
choisit le rendu (`asciidoc` par défaut, `markdown`, `html`, `csv`, `json`) ; le
JSON (résumé, licences avec catégorie, paquets sans licence) est celui que lit
l'onglet *Licences* de la GUI. Formats
source acceptés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD.

### Validation de SBOM (`validate`)

Vérifie la conformité structurelle d'un ou plusieurs fichiers SBOM :

```bash
# Valider un fichier
./sbom_generator validate sbom.cdx.json
# → sbom.cdx.json : OK (CycloneDX 1.6)

# Valider plusieurs fichiers en une passe (exit 1 si au moins un invalide)
./sbom_generator validate sbom.cdx.json sbom.spdx.json

# Mode strict (les champs recommandés sont aussi vérifiés)
./sbom_generator validate --strict sbom.cdx.json
```

Codes de retour : `0` = tous valides, `1` = au moins un fichier invalide ou introuvable.

### Analyse de vulnérabilités (`scan`)

Interroge un ou plusieurs scanners sur un SBOM déjà généré, avec filtrage
par date de publication/modification :

```bash
# Grype (défaut), toutes les CVE
./sbom_generator scan --sbom sbom.cdx.json

# Toutes les CVE grype depuis 2024
./sbom_generator scan --sbom sbom.cdx.json --cve-after 2024-01-01

# OSV-Scanner entre deux dates
./sbom_generator scan --sbom sbom.cdx.json --scanner osv \
  --cve-after 2023-06-01 --cve-before 2024-01-01

# Les trois scanners, champ "dernière modification", CVE sans date incluses
./sbom_generator scan --sbom sbom.cdx.json --scanner all \
  --cve-date-field modified --cve-after 2023-01-01 --include-undated

# Export SARIF (intégration GitHub Code Scanning) vers un fichier
./sbom_generator scan --sbom sbom.cdx.json --scanner all \
  --format sarif --output resultats.sarif

# Rapport de synthèse inter-scanners (markdown | asciidoc | pdf)
./sbom_generator scan --sbom sbom.cdx.json --scanner all \
  --format pdf --output scan-report.pdf

# Priorisation par exploitabilité
./sbom_generator scan --sbom sbom.cdx.json --only-kev --sort risk
./sbom_generator scan --sbom sbom.cdx.json --epss-min 0.1
./sbom_generator scan --sbom sbom.cdx.json --no-enrich   # hors-ligne (CI)
```

Scanners disponibles (`--scanner`) : `grype` (défaut), `osv`, `trivy`, ou
`all` pour les trois. Champ de date (`--cve-date-field`) : `published`
(défaut), `modified`, ou `latest` (la plus récente des deux). Format de
sortie (`--format`) : `text` (défaut, coloré console), `sarif` (SARIF 2.1.0),
ou `markdown` / `asciidoc` / `pdf` (rapport de synthèse inter-scanners écrit
dans `--output` — résumé, matrice CVE × scanner, section « Priorisation par
risque »). Résultats `text` triés par sévérité décroissante, ou par risque
avec `--sort risk`. L'absence d'un scanner demandé est signalée sans faire
échouer les autres. Codes de retour (`text` / `sarif`) : `0` = aucune
vulnérabilité dans la plage demandée, `1` = au moins une trouvée (ou erreur
de scanner) ; les formats rapport renvoient `0` dès qu'un fichier est écrit.

**Vulnérabilités par couche d'image (`--per-layer`)** : rattache chaque CVE
à la couche de l'image qui apporte le paquet vulnérable.

```bash
# Image analysée directement : jeu de SBOM par couche généré à la volée
./sbom_generator scan --image ./app.tar --per-layer --scanner all

# SBOM de chaque couche scanné, couches calculées en mode rootfs, rapport PDF
./sbom_generator scan --image nginx:latest --per-layer --layer-scan each \
  --layer-mode rootfs --scanner all -f pdf -o nginx-couches.pdf

# À partir d'un jeu déjà produit par --per-layer (SBOM de couche à côté)
./sbom_generator scan --sbom out/app.cdx.json --per-layer
```

| `--layer-scan` | Principe | Ce qu'on voit |
|---|---|---|
| `attribute` *(défaut)* | un seul scan du SBOM global ; chaque CVE est rattachée à la couche d'origine de son paquet (`sbom_generator:layer:index`) | les CVE de l'image finale, par couche qui les a introduites |
| `each` | le SBOM de chaque couche est scanné séparément | en plus, les CVE d'une version introduite par une couche puis remplacée plus haut (avec `--layer-mode rootfs`) ; une CVE peut apparaître dans plusieurs couches |

`--image` (exclusif de `--sbom`) génère d'abord le SBOM CycloneDX de l'image
(`--oci-tool`, défaut `syft` ; avec `--per-layer`, aussi les SBOM de couche,
`--layer-mode` au choix) dans un répertoire temporaire supprimé en fin
d'exécution. Sortie texte : colonne `COUCHE` et tableau « CVE par couche »
(digest, instruction, nombre de CVE, critiques, élevées) ; SARIF : propriété
`layer` ; rapports markdown/asciidoc/pdf : section « Couches de l'image » et
colonne « Couche(s) » dans la comparaison inter-scanners. En `attribute`, une
CVE dont le paquet est absent du SBOM global reste sans couche (signalé).

**Exploitabilité et exploitation active** : chaque CVE est enrichie (actif
par défaut) avec **CISA KEV** (exploitée dans la nature), **EPSS**
(probabilité d'exploitation à 30 j), un signal **PoC public** et le
sous-score d'**exploitabilité CVSS**. Colonnes `KEV` / `EPSS` / `PoC` en
`--format text`, propriétés `kev` / `epss` / `poc` en SARIF, section dédiée
dans les rapports. `--no-enrich` (ou `SBOMGEN_OFFLINE=1`) coupe toute requête
réseau ; `--no-poc` ne coupe que la source tierce. Filtres : `--only-kev`,
`--epss-min <0..1>`. Cache 24 h sous `~/.cache/sbom-generator/`.

**Pourquoi les scanners ne trouvent pas les mêmes CVE** : avec `--scanner
all`, une bonne partie des CVE sont normalement signalées par un seul
outil. Cause principale : nomenclature d'identifiant différente — sur les
paquets Java, Grype nomme ses trouvailles en `GHSA-*` (GitHub Security
Advisories, sa source principale pour ce langage) tandis que Trivy préfère
le CVE correspondant ; c'est la même vulnérabilité sous deux noms
différents (Grype liste le CVE lié dans `relatedVulnerabilities`). Sur une
image RHEL 9.6/Keycloak de référence, l'accord brut entre Grype et Trivy
n'était que de 72 CVE communes sur ~210 identifiants uniques de chaque
côté ; après résolution des alias `GHSA-*` → CVE côté Java, il montait à
~98 % (les paquets RPM, où les deux outils utilisent nativement le CVE,
étaient déjà d'accord à ~94 %). Le résidu s'explique par la
fraîcheur/couverture différente des bases de vulnérabilités (Anchore DB
pour Grype, `trivy-db` pour Trivy). Voir `doc/usage.adoc` pour le détail.

---

### Rapport de conformité Cyber Resilience Act (`cra`)

Produit un rapport de conformité au Règlement (UE) 2024/2847 (*Cyber
Resilience Act*) à partir d'un SBOM et, optionnellement, d'une analyse de
vulnérabilités.

```bash
# Rapport PDF, métadonnées depuis cra.yaml, analyse Grype
./sbom_generator cra --sbom sbom.cdx.json --config cra.yaml -o rapport-cra.pdf

# Rapport JSON machine-lisible, sans analyse de vulnérabilités
./sbom_generator cra --sbom sbom.cdx.json --no-scan --format json

# Métadonnées en ligne de commande (elles priment sur cra.yaml)
./sbom_generator cra --sbom sbom.cdx.json --manufacturer "ACME Corp" \
  --product WidgetOS --product-version 3.2.1 -o rapport-cra.pdf
```

**Périmètre : sous-ensemble vérifiable automatiquement uniquement.** Le
rapport évalue le **format et la complétude du SBOM** (format lisible par
machine, couverture des dépendances, champs BSI TR-03183-2 par composant,
éléments minimaux NTIA 2021), la **gestion des vulnérabilités connues**
(inventaire + disponibilité des correctifs, via `--scan`) et signale toute
CVE au **catalogue CISA KEV** comme déclenchant l'obligation de notification
à l'ENISA **sous 24 h** (art. 14). Les autres obligations du CRA (diffusion
sécurisée des mises à jour, divulgation coordonnée, conception sûre par
défaut, notifications réglementaires, déclaration UE de conformité) relèvent
du fabricant et sont seulement listées. **Ce document n'est pas une
déclaration de conformité.**

Options : `--sbom/-s` (obligatoire), `--config/-c <cra.yaml>` (par défaut
`./cra.yaml` s'il existe), `--manufacturer` / `--product` /
`--product-version` / `--support-until` / `--vuln-contact` /
`--cvd-policy-url` (métadonnées ; priment sur le fichier ; à défaut déduites
de `metadata.component` du SBOM), `--scan` / `--no-scan` (défaut activé),
`--scanner <grype|osv|trivy|all>` (défaut `grype`), `--enrich` /
`--no-enrich`, `--format <pdf|asciidoc|json>` (défaut `pdf`), `--output/-o`.
Codes de retour : `0` = conforme (avec ou sans réserve sur le périmètre
vérifié), `2` = non conforme (point bloquant : format non lisible par
machine, champ obligatoire manquant, vulnérabilité sans correctif, CVE
activement exploitée).

Fichier `cra.yaml` (clés facultatives, `clé: valeur` par ligne, `#` pour un
commentaire) :

```yaml
manufacturer: "ACME Corp"
product: "WidgetOS"
product_version: "3.2.1"
support_until: "2030-12-31"
vulnerability_contact: "security@acme.example"
cvd_policy_url: "https://acme.example/security/policy"
```

---

## Ce que contient le SBOM généré

### Métadonnées du document

| Champ | Contenu |
|-------|---------|
| Timestamp | Date/heure de génération (UTC ISO 8601) |
| Outil | `sbom_generator 1.5.15` |
| Auteur | Fixé à `sbom_generator` (non configurable) |
| Supplier | Fixé à `local` (non configurable) |
| Nom du composant racine | Configurable via `--name` (défaut : `Package Set`) |
| Lifecycle | `operations` (par défaut) |
| Data license | `CC0-1.0` |

### Par composant

| Champ | Description |
|-------|-------------|
| Nom, version | Selon le type de paquet (voir « Types de références acceptées ») |
| PURL | Identifiant de paquet universel, calculé selon l'écosystème |
| CPE 2.3 | Calculé uniquement pour les paquets RPM |
| Empreinte(s) | Condensat du paquet/artefact quand il est connu sans requête réseau : `integrity` des lockfiles npm/yarn, `sha256` de `pubspec.lock`, `Digest` Trivy / digests Syft (images OCI), SHA-256+SHA-512 calculés pour un fichier `.rpm`/`.deb`/`.jar`/`.whl` passé en entrée, `%{SIGMD5}` (MD5) pour un paquet RPM installé interrogé par nom. Émise en `hashes` (CycloneDX), `checksums` (SPDX 2.3), `verifiedUsing` (SPDX 3.0). Le hash de l'en-tête RPM est exposé à part (`rpm:header-sha256`). Souvent absente pour les paquets système d'une image. |
| Licence | Normalisée vers SPDX (expression ou identifiant) |
| Supplier | Repris de la source : `%{VENDOR}` (RPM), `Maintainer` (Debian), `maintainer`/`Vendor` (OCI), `Author-email` (wheel), `groupId` (Maven), `author` du `package.json` (npm). Absent des lockfiles Go/pip/pub/yarn → `--supplier "<nom>"` sert de repli (n'écrase jamais une valeur détectée). Inconnu ⇒ `NOASSERTION` en SPDX 2.3, clé omise en CycloneDX |
| Description | Résumé court, quand disponible |
| Propriétés additionnelles | Spécifiques à l'écosystème (`rpm:*`, `deb:*`, `pypi:*`…) |

### Dépendances

Les dépendances sont résolues **au sein de la liste fournie**, uniquement
pour les paquets système (RPM) et par écosystème compatible (ex. Python ↔
Python) :
- Résolution : si le paquet A requiert une capability que le paquet B
  fournit, une relation `A → B` est ajoutée.
- Les dépendances externes non présentes dans la liste apparaissent dans les
  propriétés (`rpm:requires`…) mais pas dans `dependsOn` — pas de résolution
  transitive.

---

## Formats de sortie en détail

### CycloneDX 1.6 / 1.7 (`cyclonedx`)

Structure JSON (1.6, par défaut) :
```
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": { timestamp, tools, authors, supplier, lifecycles, licenses, component },
  "components": [ { type, bom-ref, name, version, purl, cpe, hashes, licenses,
                     supplier, externalReferences, properties } ],
  "dependencies": [ { ref, dependsOn[] } ],
  "compositions": [ { aggregate, assemblies[], dependencies[] } ]
}
```

Avec `--cyclonedx-version 1.7`, des champs supplémentaires apparaissent
selon les options fournies (absents du schéma 1.6, donc n'apparaissent
jamais en 1.6) :
- `metadata.distributionConstraints.tlp` — via `--tlp`
- `citations[]` racine, attribuant `/components` à l'outil source —
  automatique dès que `--image` est utilisé (attribution à `--oci-tool`)
- `components[].patentAssertions[]` + `definitions.patents[]` — via `--patent-map`

#### Déclarations de brevets (`--patent-map`)

Fichier texte, une déclaration par ligne :
```text
package_name: numéro_brevet|juridiction|statut_légal|type_assertion
openssl: US1234567|US|granted|license
```
- `juridiction` : code WIPO ST.3 à 2 lettres (`US`, `EP`, `JP`…)
- `statut_légal` : `pending`, `granted`, `revoked`, `expired`, `lapsed`, `withdrawn`, `abandoned`, `suspended`, `reinstated`, `opposed`, `terminated`, `invalidated`, `in-force`
- `type_assertion` : `ownership`, `license`, `third-party-claim`, `standards-inclusion`, `prior-art`, `exclusive-rights`, `non-assertion`, `research-or-evaluation`

### SPDX 2.3 (`spdx`)

```
{
  "spdxVersion": "SPDX-2.3",
  "creationInfo": { created, creators },
  "packages": [ { SPDXID, name, versionInfo, downloadLocation, licenseConcluded,
                   licenseDeclared, copyrightText, externalRefs, annotations } ],
  "relationships": [ { spdxElementId, relationshipType, relatedSpdxElement } ]
}
```

Types de relations : `DESCRIBES` (document → paquets) et `DEPENDS_ON`
(dépendances résolues).

### SPDX 3.0 JSON-LD (`spdx3`)

```
{
  "@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
  "@graph": [
    { type: "SpdxDocument", profileConformance: ["core","software"], … },
    { type: "CreationInfo", specVersion: "3.0.0", … },
    { type: "Tool", … },
    { type: "Organization", … },         ← un par fournisseur unique
    { type: "software:Package", … },     ← un par paquet
    { type: "Relationship", relationshipType: "describes", … },
    { type: "Relationship", relationshipType: "dependsOn", … }
  ]
}
```

### JSON personnalisé (`json`)

Inclut toutes les métadonnées brutes (`requires`, `provides`) ainsi que les
dépendances résolues en noms lisibles. Idéal pour du scripting ou de
l'intégration personnalisée.

---

## Scores de qualité sbomqs

Exemple de sortie (`sbomqs score --basic sbom.cdx.json`) :

```
SBOM Quality Score: 7.8/10.0   Grade: C

Identification  : 10.0/10  A    ← noms, versions, identifiants locaux
Provenance      : 10.0/10  A    ← auteur, supplier, timestamp, lifecycle
Integrity       :  8.9/10  B    ← checksums SHA-256 (hors signature)
Completeness    :  6.0/10  D    ← supplier, source code, primary component
Licensing       :  2.5/10  F    ← limitation sbomqs v2.0.6 pour CycloneDX
Vulnerability   :  9.9/10  A    ← PURL + CPE 2.3
Structural      : 10.0/10  A    ← schéma valide, spec déclarée

NTIA 2021       : 10.0/10  A
NTIA 2025 RFC   : 10.0/10  A
```

### Limitations connues (sbomqs v2.0.6)

> `comp_with_licenses` et `comp_with_valid_licenses` **ne sont pas
> implémentés** pour CycloneDX dans cette version de sbomqs (toujours 0,
> indépendamment du contenu).

- `comp_with_dependencies` : le mécanisme `compositions` n'est pas reconnu
- `sbom_signature` : nécessite une clé cryptographique externe

---

## Architecture du projet

```
sbom_generator/
├── bin/
│   └── sbom_generator.dart        # Point d'entrée CLI (sous-commandes : diff, merge, convert, licenses, validate, scan)
├── lib/
│   ├── models.dart                 # RpmPackage, WheelPackage, DebPackage, OciPackage, PackageDependency
│   ├── rpm_parser.dart             # Interrogation rpm + résolution dépendances
│   ├── wheel_parser.dart           # Lecture wheels .whl (python3 zipfile)
│   ├── tar_parser.dart             # Lecture archives .tar/.tar.gz/.tgz
│   ├── zip_parser.dart             # Lecture archives .zip
│   ├── deb_parser.dart             # Lecture paquets .deb (dpkg-deb)
│   ├── jar_parser.dart             # Coordonnées Maven d'un .jar (unzip -p pom.properties)
│   ├── requirements_parser.dart    # Lecture requirements.txt (pur Dart)
│   ├── go_parser.dart              # Lecture go.sum et go.mod (pur Dart)
│   ├── npm_parser.dart             # Lecture package-lock.json v1/v2/v3 (pur Dart)
│   ├── yarn_parser.dart            # Lecture yarn.lock v1 et v2+ Berry (pur Dart)
│   ├── maven_parser.dart           # Lecture pom.xml (pur Dart, extraction XML légère)
│   ├── oci_parser.dart             # Analyse images OCI (syft / trivy / skopeo)
│   ├── archive_helpers.dart        # Helpers partagés tar + zip
│   ├── license_normalizer.dart     # Normalisation SPDX centralisée
│   ├── sbom_diff.dart              # Comparaison de SBOM (sous-commande diff)
│   ├── sbom_merger.dart            # Fusion de SBOM (sous-commande merge)
│   ├── sbom_reader.dart            # Lecteur SBOM (CycloneDX/SPDX) → List<Package>
│   ├── license_report_generator.dart # Rapport de licences AsciiDoc (sous-commande licenses)
│   ├── scan_report_generator.dart  # Rapport de synthèse inter-scanners (scan -f md/adoc/pdf)
│   ├── vuln_enrichment.dart        # Enrichissement CVE : CISA KEV, EPSS, PoC, exploitabilité CVSS
│   ├── policy_checker.dart         # Licences interdites + score qualité CI/CD
│   ├── cyclonedx_generator.dart    # Générateur CycloneDX 1.6/1.7
│   ├── spdx_generator.dart         # Générateur SPDX 2.3
│   ├── spdx3_generator.dart        # Générateur SPDX 3.0 JSON-LD
│   ├── simple_json_generator.dart  # Générateur JSON personnalisé
│   ├── markdown_generator.dart     # Tableau Markdown des licences
│   ├── asciidoc_generator.dart     # Tableau AsciiDoc des licences
│   ├── html_generator.dart         # Rapport HTML interactif autonome
│   └── csv_generator.dart          # Export CSV (RFC 4180)
├── doc/
│   ├── developer.adoc              # Documentation développeur
│   └── usage.adoc                  # Guide d'utilisation détaillé
├── test/
│   ├── unit/                       # Tests unitaires
│   └── integration/                # Tests d'intégration
├── scripts/                        # Build, installation, désinstallation
├── example/3PP/                    # Exemples d'archives tierces
└── pubspec.yaml                    # Dépendances Dart (args ^2.4.2)
```

---

## Dépannage

### `rpm: command not found`

```bash
# Fedora/RHEL
sudo dnf install rpm
# Debian/Ubuntu
sudo apt install rpm
```

### `python3 not found — required to read .whl, tar, and zip archives`

```bash
# Fedora/RHEL
sudo dnf install python3
# Debian/Ubuntu
sudo apt install python3
```

### `dpkg-deb not found — required to read .deb files`

```bash
# Fedora/RHEL
sudo dnf install dpkg
# Debian/Ubuntu
sudo apt install dpkg
```

### `unzip not found — required to read .jar files`

```bash
# Fedora/RHEL
sudo dnf install unzip
# Debian/Ubuntu
sudo apt install unzip
```

### `Warning: cannot query "pkg"`

Le paquet n'est pas installé ou le fichier `.rpm` est inaccessible.
Vérifiez avec `rpm -q <paquet>` ou `rpm -qp <fichier.rpm>`.

### Doublons dans la liste d'entrée

Si le même paquet (même `bomRef`) apparaît plusieurs fois, il n'est inclus
qu'une seule fois dans le SBOM. Un message `($N doublon(s) supprimé(s))`
l'indique.

### `syft / trivy / skopeo: command not found`

L'outil OCI demandé n'est pas installé ou n'est pas dans le `PATH`.
Installez-le via son script officiel ou le gestionnaire de paquets du
système. Vérifiez avec `which syft`, `which trivy` ou `which skopeo`.

### `Échec de l'analyse OCI : …`

- Vérifiez que la référence est accessible : `docker pull <image>` ou
  `skopeo inspect docker://<image>`
- Pour un registre privé, authentifiez-vous au préalable : `docker login`,
  `skopeo login`
- Pour une archive locale, vérifiez que le fichier existe : `ls -lh
  /path/image.tar` (les formats `.tar`, `.tar.gz` et `.tgz` sont supportés)

### Fichier SBOM très volumineux

Les propriétés `rpm:requires` peuvent représenter 50 à 150 entrées par
paquet ; sur plusieurs centaines de paquets, le fichier CycloneDX peut
atteindre plusieurs Mo. C'est normal. Les images OCI peuvent aussi contenir
plusieurs centaines de paquets (images de base : ~100, images applicatives
complexes : 300–800).
