# sbom_generator — Documentation développeur

Ce document explique le fonctionnement interne du code pour une prise en main rapide.

> Une version plus détaillée (AsciiDoc, avec table des matières) existe dans
> `doc/developer.adoc`. Ce fichier reste la référence rapide au format Markdown.

---

## Architecture générale

Le programme suit un pipeline concurrent, capable de combiner plusieurs sources
(fichier liste, archive/paquet unique, dossier scanné récursivement, image OCI) :

```
--input (fichier liste / archive unique / dossier)     --image (registre / tar / OCI layout)
        │                                                       │
        ├─ requirements.txt ──► RequirementsParser (pré-expansion, 1:N)
        ├─ go.sum / go.mod ────► GoParser            (pré-expansion, 1:N)
        ├─ package-lock.json ──► NpmParser           (pré-expansion, 1:N)
        ├─ yarn.lock ──────────► YarnParser          (pré-expansion, 1:N)
        ├─ pom.xml ────────────► MavenParser         (pré-expansion, 1:N)
        │                                                       │
        ▼                                                       ▼
┌────────────────────────────────────────────┐        OciParser (syft / trivy / skopeo)
│  bin/sbom_generator.dart                    │        → { packages: List<OciPackage>, os: OsInfo? }
│  (main + _Semaphore + _printProgress)       │                │
│  1. Lecture + validation CLI                │◄───────────────┘
│  2. Détection du type par extension         │
│  3. Dispatch concurrent (--concurrency N)   │
│  4. Déduplication par bomRef                │
└──┬──────┬──────┬──────┬──────┬──────────────┘
   │      │      │      │      │
   ▼      ▼      ▼      ▼      ▼
  Rpm   Wheel   Tar   Zip   Deb    Jar
Parser Parser Parser Parser Parser Parser
               └──┬───┘
                  ▼
          archive_helpers.dart
    (parseArchiveFilename, identifyArchiveLicense)

              │  List<Package>  (RpmPackage | WheelPackage | DebPackage | OciPackage)
              ▼
   RpmParser.buildDependencies()
              │  List<PackageDependency>
              ▼
       LicenseNormalizer ◄─── importé par tous les générateurs JSON/JSON-LD
              │
              ▼
┌─────────────────────────────────────────────┐
│  cyclonedx_generator.dart   (1.6 / 1.7)      │
│  spdx_generator.dart                         │
│  spdx3_generator.dart            (choix      │
│  simple_json_generator.dart       selon -f,  │
│  markdown_generator.dart          répétable) │
│  asciidoc_generator.dart                     │
│  html_generator.dart                         │
│  csv_generator.dart                          │
└─────────────────────────────────────────────┘
              │
              ▼
   Fichier(s) SBOM (.cdx.json / .spdx.json / .spdx3.jsonld / .custom.json /
                     .md / .adoc / .html / .csv)
              │
              ▼
   policy_checker.dart  (--deny-license, --min-quality-score → exit 2 si violation)
              │
              ▼
   cosign sign-blob     (--sign, best-effort)
```

En complément de la génération, six sous-commandes réutilisent tout ou
partie du pipeline sans reconstruire un SBOM depuis les paquets :

| Sous-commande | Fichier(s) impliqué(s) | Rôle |
|---|---|---|
| `diff <a> <b>` | `sbom_diff.dart` | Compare deux SBOM CycloneDX ou SPDX (2.x/3.0) (ajouts/suppressions/mises à jour) |
| `merge <a> <b> …` | `sbom_merger.dart` | Fusionne plusieurs SBOM CycloneDX ou SPDX 2.x en un seul, déduplication par PURL |
| `convert -i <a> -f <fmt>` | `sbom_reader.dart` + générateurs | Relit un SBOM existant et le réexporte vers un/plusieurs formats |
| `licenses -i <a> -o <adoc>` | `sbom_reader.dart` + `license_report_generator.dart` | Rapport AsciiDoc des licences, regroupé par licence, avec alertes copyleft |
| `validate <a> [<b>…]` | (inline dans `bin/sbom_generator.dart`) | Vérifie la structure minimale d'un ou plusieurs SBOM |
| `scan --sbom <a>` | (inline dans `bin/sbom_generator.dart`) | Interroge grype/osv-scanner/trivy sur un SBOM déjà généré, filtre par date |

Tous les générateurs et le lecteur SBOM travaillent sur `List<Package>` — la
classe abstraite commune à `RpmPackage`, `WheelPackage`, `DebPackage` et
`OciPackage`.

---

## `lib/models.dart` — Hiérarchie de types

### Classe abstraite `Package`

Interface commune à tous les types de paquets. Tous les générateurs et
`buildDependencies` travaillent exclusivement avec cette interface.

```dart
abstract class Package {
  // Champs communs
  String get name;
  String get version;
  String get license;
  String get url;
  String get summary;
  String get vendor;
  String get arch;
  String get sourceRef;
  String get sha256Header;
  List<String> get requires;
  List<String> get provides;

  // Identifiants calculés
  String get fullVersion;   // version affichable
  String get purl;          // Package URL (purl-spec)
  String get bomRef;        // identifiant CycloneDX unique
  String get spdxId;        // identifiant SPDX (SPDXRef-…)
  String get packageType;   // 'rpm' | 'pypi' | 'source' | 'deb' | 'maven' | 'golang' | 'npm' | …
}
```

### Classe `OsInfo` (hors hiérarchie `Package`)

```dart
class OsInfo {
  final String id;          // ex. 'redhat', 'debian', 'alpine'
  final String version;     // ex. '9.6', '13.5'
  final String? prettyName; // ex. 'Red Hat Enterprise Linux 9.6 (Plow)'
  final String? cpe;
}
```

OS de base d'une image de conteneur, extrait par `OciParser.parseImage()`
(voir `lib/oci_parser.dart` plus bas) quand `--image` utilise le backend
syft ou trivy. Sert à générer un composant dédié dans les SBOM
CycloneDX/SPDX — voir la section `OsInfo` sous `lib/oci_parser.dart`.

La fonction utilitaire de bibliothèque `_safeId(String s)` remplace tout
caractère hors `[a-zA-Z0-9._-]` par `-`. Elle est utilisée dans les
implémentations de `bomRef` et `spdxId`.

### `RpmPackage extends Package`

Représente un paquet RPM après interrogation. Champs supplémentaires
(RPM-spécifiques) :

| Champ | Source RPM | Exemple |
|-------|-----------|---------|
| `release` | `%{RELEASE}` | `6.el9` |
| `epoch` | `%{EPOCH}` | `1` ou `(none)` |
| `buildTime` | `%{BUILDTIME}` | timestamp Unix |
| `sourceRpm` | `%{SOURCERPM}` | `bash-5.1.8-6.el9.src.rpm` |

Identifiants calculés :

| Getter | Exemple |
|--------|---------|
| `fullVersion` | `5.1.8-6.el9` ou `1:5.1.8-6.el9` (epoch si non nul) |
| `purl` | `pkg:rpm/bash@5.1.8-6.el9?arch=x86_64` |
| `bomRef` | `pkg-bash-5.1.8-6.el9-x86_64` |
| `spdxId` | `SPDXRef-bash-5.1.8-6.el9` |
| `packageType` | `'rpm'` |

> **Piège :** Le `bomRef` inclut version ET release. Deux fichiers `.rpm` du
> même paquet depuis des dépôts différents produisent le même `bomRef`. La
> déduplication dans `main()` gère ce cas.

### `WheelPackage extends Package`

Représente un paquet dont l'identité provient d'un écosystème « léger » sans
appel `rpm`/`dpkg-deb` : wheel/sdist Python, archive générique, module Go,
paquet npm/yarn, dépendance Maven. Le comportement dépend de `packageType` :

| `packageType` | Source | PURL | bomRef prefix |
|---------------|--------|------|---------------|
| `'pypi'` | wheel `.whl`, Python sdist (PKG-INFO présent), `requirements.txt` | `pkg:pypi/<name>@<ver>` | `pkg-pypi-` |
| `'source'` | archive générique sans métadonnées Python | `pkg:generic/<name>@<ver>` | `pkg-src-` |
| `'maven'` | `pom.xml` (dépendances) ou `.jar` autonome | `pkg:maven/<groupId>/<artifactId>@<ver>` | `pkg-maven-` |
| `'golang'` | `go.sum` / `go.mod` | `pkg:golang/<module>@<ver>` | `pkg-golang-` |
| `'npm'` | `package-lock.json` / `yarn.lock` | `pkg:npm/<name>@<ver>` | `pkg-npm-` |

Le nom Python est normalisé selon PEP 503 dans le PURL (`_normalizePyName` :
minuscules, `[-_.]+ → -`). Pour `packageType == 'maven'`, `name` est stocké
sous la forme `"groupId:artifactId"` — le getter `purl` sépare les deux
segments pour reconstruire `pkg:maven/<groupId>/<artifactId>@<ver>`.

Le champ `arch` contient le platform tag du wheel (ex. `any`,
`linux_x86_64`), l'architecture détectée depuis le nom de fichier pour les
archives génériques, ou `'any'` pour les écosystèmes sans notion
d'architecture (Go, npm, Maven).

### `DebPackage extends Package`

Représente un paquet Debian extrait par `dpkg-deb -f`. Champs supplémentaires :

| Champ | Source control | Exemple |
|-------|---------------|---------|
| `arch` | `Architecture` | `amd64` |
| `vendor` | `Maintainer` | `Ubuntu Developers` |
| `url` | `Homepage` | `https://…` |
| `summary` | première ligne de `Description` | `OpenSSL shared library` |
| `requires` | `Depends` + `Pre-Depends` (split virgule/pipe, contraintes retirées) | `["libc6", "libssl3"]` |
| `provides` | `Provides` | `["libssl3"]` |

Identifiants calculés :

| Getter | Exemple |
|--------|---------|
| `purl` | `pkg:deb/libssl3@3.0.1?arch=amd64` |
| `bomRef` | `pkg-deb-libssl3-3.0.1-amd64` |
| `spdxId` | `SPDXRef-deb-libssl3-3.0.1` |
| `packageType` | `'deb'` |

### `OciPackage extends Package`

Représente un paquet extrait d'une image de conteneur par `OciParser`
(`--image`). Le champ `packageType` reflète l'écosystème détecté par l'outil
d'analyse choisi (`--oci-tool`) : `'rpm'`, `'deb'`, `'apk'`, `'pypi'`,
`'npm'`, `'go'`, `'java'`, `'nuget'`, `'cargo'`, ou `'generic'` en repli.

Champ supplémentaire `purlOverride` : PURL fourni directement par l'outil
d'analyse (syft/trivy) ; si non vide, il est utilisé tel quel sans
reconstruction manuelle. Le champ `imageRef` conserve la référence OCI
d'origine (registre, chemin d'archive tar, ou répertoire OCI layout) pour
traçabilité.

Identifiants calculés :

| Getter | Exemple |
|--------|---------|
| `purl` | `purlOverride` si fourni, sinon reconstruit selon `packageType` |
| `bomRef` | `pkg-oci-<type>-<name>-<version>` |
| `spdxId` | `SPDXRef-oci-<name>-<version>` |
| `fullVersion` | `version` brut (pas de release ni epoch) |

### `PackageDependency`

Structure simple liant un `bomRef` source à la liste des `bomRef` cibles dont
il dépend.

```dart
class PackageDependency {
  final String sourceRef;      // bomRef du paquet source
  final List<String> dependsOn; // liste de bomRef des dépendances
}
```

### `generateUuidV4()`

Fonction libre générant un UUID v4 RFC 4122 via `Random.secure()`. Utilisée
dans tous les générateurs pour `serialNumber` / `documentNamespace`.

---

## `lib/rpm_parser.dart` — Interrogation RPM

### Constante `_queryFormat`

```dart
static const _queryFormat =
    r'%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{EPOCH}|%{LICENSE}|%{VENDOR}|%{URL}|%{BUILDTIME}|%{SHA256HEADER}|%{SOURCERPM}|%{SUMMARY}\n';
```

`SUMMARY` est en dernier car il peut contenir des `|`. Le parser rejoint tous
les fragments ≥ index 11 en cas de split excédentaire.

### `parsePackage(String packageRef)`

Les trois appels `rpm` sont lancés en **parallèle** via `Future.wait` :

```dart
final results = await Future.wait([
  Process.run('rpm', [qFlag, '--queryformat', _queryFormat, packageRef]),
  Process.run('rpm', [qFlag, '--requires', packageRef]),
  Process.run('rpm', [qFlag, '--provides', packageRef]),
]);
```

1. `rpm -q[p] --queryformat ...` → 12 champs de métadonnées
2. `rpm -q[p] --requires` → liste des capabilities requises (parsée par `_parseCapabilities`)
3. `rpm -q[p] --provides` → liste des capabilities fournies (parsée par `_parseCapabilities`)

Retourne `null` avec un avertissement sur `stderr` si le premier appel échoue.

### `buildDependencies(List<Package> packages)`

Accepte une liste mixte (RPM + tout écosystème « léger »). L'algorithme
fonctionne en deux passes :

**Passe 1 — construction de `providesMap`**

```
providesMap : capability name → bomRef
```

Pour chaque paquet : le `name` du paquet + chaque entrée de `provides` sont
ajoutés. Les paquets non-RPM incluent leur nom normalisé dans `provides`, ce
qui permet la résolution intra-écosystème (ex. Python ↔ Python).

**Passe 2 — résolution des `requires`**

Chaque entrée de `requires` est normalisée via `_capabilityName()` puis
cherchée dans `providesMap`. Une dépendance n'est ajoutée que si la cible est
dans la liste (`knownRefs`) — pas de résolution transitive.

### `_capabilityName(String capability)`

```dart
return capability.split(RegExp(r'\s+[<>=!]'))[0].trim();
```

| Entrée | Sortie |
|--------|--------|
| `bash >= 4.1` | `bash` |
| `python3dist(lxml) >= 3.0` | `python3dist(lxml)` |
| `libc.so.6(GLIBC_2.17)(64bit)` | `libc.so.6(GLIBC_2.17)(64bit)` |
| `/bin/sh` | `/bin/sh` |

---

## `lib/wheel_parser.dart` — Lecture des wheels Python

Le wheel est un ZIP contenant un répertoire `{name}-{version}.dist-info/METADATA`.
La classe utilise `python3 zipfile` pour extraire ce fichier sans dézipper
l'archive entière.

### `parseWheelFile(String path)`

Appelle python3, récupère le texte METADATA, délègue à `_buildPackage()`.

### `parseMetadataText(String sourceRef, String text, {String packageType})`

**Point d'extension public** utilisé par `TarParser`/`ZipParser` pour
réutiliser le parseur RFC 822 sans dupliquer le code.

### Extraction des champs clés

| Champ METADATA | Priorité | Fallback |
|---------------|----------|---------|
| License | `License-Expression` (PEP 639) | `License` → classifiers `License :: OSI Approved :: …` |
| URL | `Project-URL: Homepage, …` | `Home-page` |
| Vendor | `Author-email` (strip `<addr>`) | `Author` → `Maintainer` |
| Arch | dernier segment `-` avant `.whl` | `any` |
| Requires | `Requires-Dist` (strip contraintes et markers) | — |

### Résolution de dépendances Python

`WheelPackage.provides = [normalizedName]` (nom normalisé PEP 503).
`buildDependencies` ajoute aussi `pkg.name` à `providesMap`, couvrant à la
fois le nom brut et le nom normalisé.

---

## `lib/tar_parser.dart` — Lecture des archives tar

Le script Python embarqué (`python3 -c`) retourne un objet JSON sur stdout :

```json
{"type": "python", "content": "<texte RFC 822>"}
```
ou
```json
{"type": "generic", "licenseFile": "LICENSE", "license": "<2 KB du fichier>"}
```

**Logique de détection** (dans cet ordre) :
1. Cherche `*.dist-info/METADATA` ou `**/PKG-INFO` → type `python`
2. Cherche `LICENSE`, `COPYING`, `LICENSE-*`, `LICENCE`, `COPYING.*` à
   profondeur ≤ 2 → type `generic` avec le contenu du premier fichier trouvé

Si `type == 'python'` : délègue à `WheelParser().parseMetadataText()`.
Si `type == 'generic'` : délègue à `buildGenericArchivePackage()` (depuis
`archive_helpers.dart`).

---

## `lib/license_normalizer.dart` — Normalisation SPDX centralisée

Factorisation de la logique de normalisation des licences, importée par
`cyclonedx_generator.dart`, `spdx_generator.dart` et `spdx3_generator.dart`.

### `LicenseNormalizer` (méthodes toutes `static`)

| Méthode | Retour | Usage |
|---------|--------|-------|
| `toSpdxExpression(String raw)` | `String` | Expression SPDX pour SPDX 2.3 / 3.0 |
| `toCycloneDxLicenses(String raw)` | `List<Map<String, dynamic>>` | Structure `licenses[]` CycloneDX 1.6/1.7 |

### Algorithme commun

1. Cas vide / `(none)` → retourne vide
2. Normalisation des opérateurs booléens (`and` → `AND`, `or` → `OR`,
   `with` → `WITH`) avec regex lookbehind/lookahead `\S` pour protéger les
   tokens collés (`GPL-2.0-or-later` non altéré)
3. Détection d'expression composée (présence de `AND`/`OR`/`WITH` entourés
   d'espaces)
4. Résolution token par token dans `_sortedEntries` (tri longueur
   décroissante → évite les matches courts avant les longs)
5. Choix du champ CycloneDX : `expression` (composé), `id` (SPDX versionné
   ou `LicenseRef-*`), `name` (inconnu sans numéro)

---

## `lib/archive_helpers.dart` — Helpers partagés archives

Code partagé entre `TarParser` et `ZipParser` pour éviter la duplication.

| Symbole | Description |
|---------|-------------|
| `class ArchiveFilenameInfo` | `{String name, version, arch}` — résultat du parsing de nom de fichier |
| `parseArchiveFilename(String path)` | Analyse nom/version/arch depuis le nom de fichier (`.tar.gz`, `.tgz`, `.tar`, `.zip`) |
| `identifyArchiveLicense(String text)` | Heuristique SPDX depuis ≤ 2 000 chars du fichier licence |
| `buildGenericArchivePackage(String path, {...})` | Construit un `WheelPackage(packageType='source')` depuis les infos de filename + licence |

**Algorithme `parseArchiveFilename`** : supprime l'extension, découpe sur
`-`, trouve le premier segment `^\d+\.\d+` (version), retire les mots-clés
plateforme (`linux`, `x86_64`, `rhel8`, `systemd`, etc.) du nom.

**`identifyArchiveLicense`** : deux zones de recherche — `title` (300
premiers chars) pour les familles GPL/LGPL (évite un faux positif : le texte
GPL-2.0 mentionne « GNU Library General Public License » dans son corps mais
pas dans son titre), et `lower` (2 000 chars) pour Apache, MIT, SSPL, MPL, etc.

---

## `lib/zip_parser.dart` — Lecture des archives ZIP génériques

Même logique que `TarParser` mais pour les fichiers `.zip`, via
`python3 zipfile` au lieu de `tarfile`. Dispatch identique : `type ==
'python'` → `WheelParser.parseMetadataText()`, `type == 'generic'` →
`buildGenericArchivePackage()`.

---

## `lib/deb_parser.dart` — Lecture des paquets Debian

```bash
dpkg-deb -f /opt/pkgs/libssl3_3.0.1_amd64.deb
```

Retourne le contenu du fichier `DEBIAN/control` en RFC 822.

| Champ control | Champ `DebPackage` | Notes |
|--------------|-------------------|-------|
| `Package` | `name` | |
| `Version` | `version` | |
| `Architecture` | `arch` | |
| `License` / `X-License` | `license` | absent de nombreux `.deb` |
| `Maintainer` | `vendor` | |
| `Homepage` | `url` | |
| `Description` | `summary` | première ligne seulement |
| `Depends`, `Pre-Depends` | `requires` | split virgule puis pipe |
| `Provides` | `provides` | |

`_parseDependsList` découpe sur `,` puis sur `|` (alternatives), retire les
contraintes de version `(>= …)`. Exemple :
`"libc6 (>= 2.17) | libc6-amd64"` → `["libc6", "libc6-amd64"]`.

---

## `lib/jar_parser.dart` — Coordonnées Maven d'un `.jar` autonome

Contrairement à `MavenParser` (qui lit un manifeste `pom.xml`), `JarParser`
extrait les coordonnées Maven directement d'une archive `.jar` binaire, en
miroir de la logique déjà utilisée pour le scan d'images OCI dans
`oci_parser.dart` (`_parseMavenJars`), mais retourne des
`WheelPackage(packageType: 'maven')` — pas de notion d'`imageRef` pour un
fichier local.

**Un `.jar` peut produire plusieurs paquets.** Un jar « shaded »/uber-jar
(ex. `netty-common-*.jar`) peut embarquer, en plus de son propre
`pom.properties`, celui d'une ou plusieurs dépendances relocalisées (ex.
`org.jctools:jctools-core`). `parseJarFile` retourne donc une **liste** : le
jar lui-même en premier élément (si son identité a pu être déterminée),
suivi d'un élément par dépendance embarquée détectée — même comportement que
syft, qui liste séparément chaque `pom.properties` trouvé.

### Résolution de l'identité propre + des dépendances embarquées

1. `_readAllPomProperties` liste **tous** les
   `META-INF/maven/<groupId>/<artifactId>/pom.properties` présents dans
   l'archive (`unzip -l` puis un `unzip -p <jar> <chemin exact>` **par
   entrée**, jamais un glob concaténant plusieurs blocs).
2. Parmi ces entrées, celle dont l'`artifactId` correspond au nom de fichier
   du jar est l'identité **propre** du jar ; s'il n'y a qu'une seule entrée
   au total, elle est prise par défaut. Toutes les **autres** entrées
   deviennent des paquets supplémentaires (dépendances relocalisées).
3. Si aucune entrée ne correspond, l'identité propre retombe sur la
   convention de nom `<groupId>.<artifactId>-<version>.jar` (Quarkus/Red
   Hat), puis sur `META-INF/MANIFEST.MF` (`Bundle-SymbolicName`,
   `Implementation-Vendor-Id`, `Implementation-Title`,
   `Automatic-Module-Name`, dans cet ordre ; valeur retenue seulement si
   `_looksLikeGroupId` l'accepte : au moins un point, entièrement en
   minuscules).
4. Si le manifeste ne donne rien d'exploitable non plus, `groupId` reprend
   la valeur d'`artifactId` — dégradé mais non abandonné.
5. Liste vide (+ avertissement `stderr`) seulement si ni identité propre ni
   dépendance embarquée n'ont pu être déterminées.

> **Bug corrigé, découvert sur un jar réel** (`netty-common-4.1.100.Final.jar`) :
> lire le `pom.properties` via un glob large sans discrimination concatène
> le contenu de toutes les entrées trouvées, et un parsing clé=valeur naïf
> se fait écraser par le second bloc. Lire chaque entrée **individuellement**
> élimine ce risque.

### `_knownGroupIdOverrides` — correspondances curées (Spring Framework)

Certaines bibliothèques très répandues (les modules « core » de Spring
Framework) n'exposent leur vrai groupId (`org.springframework`) nulle part
dans le jar : seul un `Automatic-Module-Name` du type `spring.core` est
présent, qui passe `_looksLikeGroupId` mais est un nom de module JPMS, pas le
groupId Maven réel. Conséquence concrète : un scanner de vulnérabilités
associe les CVE aux vraies coordonnées Maven — avec un mauvais groupId,
aucune correspondance n'est trouvée (des CVE réelles restaient invisibles).
`_knownGroupIdOverrides` est vérifiée *avant* l'heuristique manifeste,
volontairement limitée aux ~22 modules officiels de Spring Framework.

Requiert `unzip` dans le `PATH`.

---

## `lib/oci_parser.dart` — Analyse d'images OCI

### `OciRefType` (enum)

```dart
enum OciRefType { registry, tar, ociLayout }
```

Détecté automatiquement par `OciParser.detectRefType(String ref)` :

| Valeur | Condition de détection | Exemple |
|---|---|---|
| `registry` | par défaut | `nginx:latest`, `ubuntu@sha256:…` |
| `tar` | extension `.tar`, `.tar.gz` ou `.tgz` | `/path/ubuntu.tar` |
| `ociLayout` | répertoire contenant `index.json` | `/path/oci_dir/` |

### `OciParser`

Point d'entrée : `Future<OciParseResult> parseImage(String imageRef, String tool, {bool verbose})`,
où `OciParseResult = ({List<Package> packages, OsInfo? os})` (record Dart 3).
Dispatch vers l'un des trois backends selon `tool` :

| Backend | Mécanisme |
|---|---|
| `'syft'` | `syft <ref> --output json` ; lit `artifacts[].{name, version, type, purl, licenses, metadata}` + `distro` (OS de base) |
| `'trivy'` | `trivy image --format json --quiet --list-all-pkgs <ref>` ; lit `Results[].{Type, Packages[]}` + `Metadata.OS` (OS de base) |
| `'skopeo'` | Copie via `skopeo copy` en OCI layout → extraction des layers tar → détection de la base de paquets installée (`os: null` — ne lit pas `/etc/os-release`) |

**Backend Syft** : la référence est adaptée selon `OciRefType`
(`docker-archive:<path>` pour `tar`, `oci-dir:<path>` pour `ociLayout`,
référence telle quelle pour `registry`). Les licences syft sont des objets
`{spdxExpression, value}` — `spdxExpression` est préféré si non vide.

**Backend Trivy** : lit `Results[].Type` (ex. `debian`, `centos`, `pip`) et
le normalise via `_normalizeTrivyType()` vers les écosystèmes de
`packageType`. Le PURL est lu depuis `Identifier.PURL` (trivy ≥ 0.38).

#### `OsInfo` — OS de base de l'image (`_syftDistroToOsInfo` / `_trivyMetadataToOsInfo`)

`OciParser` extrait l'OS de base de l'image (`lib/models.dart`, classe
`OsInfo { id, version, prettyName?, cpe? }`) pour permettre à
`CycloneDxGenerator`/`SpdxGenerator`/`Spdx3Generator` de générer un
composant `operating-system` dédié dans le SBOM. Sans lui, un consommateur
comme Trivy en mode `trivy sbom` ignore silencieusement toute la classe de
vulnérabilités « os-pkgs » (paquets système RPM/DEB/APK) — voir le CHANGELOG
pour le détail de ce bug et sa correction, découverte sur une image
Keycloak réelle (101 CVE `os-pkgs` manquantes sur 253).

Deux exigences non documentées de Trivy, isolées empiriquement (bissection
sur un SBOM réel, cf. `pkg/fanal/analyzer/os/release/release.go` du dépôt
aquasecurity/trivy pour la table de référence) :

- Le champ `name`/`id` du composant OS doit suivre la taxonomie interne de
  Trivy (`redhat`, `oracle`, `alma`…), pas l'`id` `/etc/os-release` que syft
  expose tel quel (`rhel`, `ol`, `almalinux`…). `_toTrivyOsFamily()` traduit
  via une table de correspondance (`_trivyOsFamilyById`) construite depuis
  la fonction `idToOSFamily` de Trivy ; les identifiants absents (`debian`,
  `ubuntu`…) sont déjà identiques à la famille Trivy attendue et passent
  inchangés. Le backend trivy n'a pas besoin de cette traduction : `Metadata.OS.Family`
  est déjà dans la taxonomie interne de Trivy.
- Côté SPDX 2.3, le `SPDXID` du paquet OS doit être préfixé
  `SPDXRef-OperatingSystem-` (pas `SPDXRef-Package-`) pour que Trivy le
  reconnaisse — `primaryPackagePurpose: "OPERATING-SYSTEM"` seul ne suffit
  pas, vérifié empiriquement.

**Backend Skopeo** — le seul entièrement « fait maison » :
1. `skopeo copy <src> oci:<tmpDir>:image` (sauf si `ociLayout` déjà présent)
2. `_extractOciLayers()` : lit `index.json` → premier manifest → liste des
   layers → `tar --extract` séquentiel dans `rootfs/`
3. Détection de la base de paquets installée : `var/lib/dpkg/status`
   (`_parseDpkgStatus`), `var/lib/rpm` (`_parseRpmRoot`, `rpm --root <dir>
   -qa`), `lib/apk/db/installed` (`_parseApkInstalled`)
4. Détection des packages applicatifs dans le rootfs : `_parseMavenJars`
   (recherche `*.jar`, extrait `pom.properties`), `_parsePythonPackages`
   (recherche `*.dist-info/METADATA` / `*.egg-info/PKG-INFO`),
   `_parseNpmPackages` (recherche `node_modules/*/package.json` premier
   niveau, ignore les paquets `"private": true`)
5. Suppression du répertoire temporaire (`chmod -R u+rwX` avant `rm -rf`
   pour les fichiers avec permissions restrictives dans certains layers)

> Seuls les paquets au statut `installed` dans `dpkg/status` sont inclus.
> Les entrées `gpg-pubkey` du registre RPM sont ignorées. syft trouve
> généralement quelques paquets de plus que skopeo sur une même image, car
> il lit aussi `MANIFEST.MF` avec des groupIds heuristiques non standard —
> gap documenté et accepté.

---

## `lib/requirements_parser.dart` — Parsing requirements.txt Python

Parser **pur Dart**, sans subprocess. Retourne `List<WheelPackage>`.

### Lignes ignorées

- Vides ou commençant par `#`
- Directives pip : `-r`, `-i`, `-e`, `-f`, `-c`

### Extraction par ligne

1. Retire les marqueurs d'environnement (`;` et suite)
2. Retire les commentaires inline (`#` et suite)
3. Retire les extras `[security]` (regex `\[.*?\]`)
4. Extrait la version après `==` (épinglée) ou le premier nombre de version sinon
5. Normalise le nom selon PEP 503 (`[-_.]+ → -`, minuscules)

### Pré-expansion des manifestes 1:N (`main()`)

Tous les parseurs pouvant produire plusieurs paquets depuis un seul fichier
sont pré-traités **avant** la boucle concurrente principale :

```dart
for (final ref in packageRefs) {
  if (_isRequirements(ref)) {
    preloadedPackages.addAll(reqParser.parseFile(ref));
  } else if (_isGoSum(ref)) {
    preloadedPackages.addAll(goParser.parseGoSum(ref));
  } else if (_isGoMod(ref)) {
    preloadedPackages.addAll(goParser.parseGoMod(ref));
  } else if (_isPackageLock(ref)) {
    preloadedPackages.addAll(npmParser.parsePackageLock(ref));
  } else if (_isYarnLock(ref)) {
    preloadedPackages.addAll(yarnParser.parseYarnLock(ref));
  } else if (_isPomXml(ref)) {
    preloadedPackages.addAll(mavenParser.parsePomXml(ref));
  } else {
    filteredRefs.add(ref);
  }
}
// … boucle Future.wait sur filteredRefs …
packages.addAll(preloadedPackages);
```

> **Pourquoi la pré-expansion ?** La boucle concurrente produit
> `Future<Package?>` (1 ref → 0 ou 1 paquet). Un fichier de manifeste peut
> contenir N paquets (cardinalité 1:N), incompatible avec ce modèle.

---

## `lib/go_parser.dart` — Modules Go

Parseur pur Dart pour `go.sum` et `go.mod`. Utilise `WheelPackage` avec
`packageType: 'golang'`.

**`parseGoSum(String path)`** : une ligne `module version hash` ou `module
version/go.mod hash`. Ignore les lignes vides/`#`, ignore les lignes dont le
2ᵉ champ se termine par `/go.mod` (doublon de checksum), retire le préfixe
`v` de la version, déduplique par `module@version`.

**`parseGoMod(String path)`** : détecte les blocs `require (…)` et les
directives `require x v` isolées, retire les commentaires `// indirect`,
retire le préfixe `v`. Les pseudo-versions (`v0.0.0-yyyymmdd-commit`) sont
conservées telles quelles.

---

## `lib/npm_parser.dart` — Paquets npm

Parseur pur Dart pour `package-lock.json` (lockfileVersion 1, 2 et 3).

```dart
final v = json['lockfileVersion'];
if (v == 1) return _parseDependenciesField(json);
return _parsePackagesField(json);   // v2 et v3
```

**`_parsePackagesField` (v2/v3)** : clé `packages` → map `{ "node_modules/pkg":
{ version, license, … } }`. Ignore la clé vide `""` (racine du projet), retire
le préfixe `node_modules/`, `_extractLicense` gère `String | List`.

**`_parseDependenciesField` (v1)** : clé `dependencies` → map récursive
(dépendances imbriquées de npm v1, traitées récursivement).

---

## `lib/yarn_parser.dart` — Paquets yarn

Parseur pur Dart pour `yarn.lock`, compatible yarn v1 (classique) et yarn v2+
(Berry). Détection de format : `content.contains('__metadata:')` → Berry,
sinon classique.

**`_parseClassic` (yarn v1)** : blocs `"pkg@^1.0.0":` suivis de lignes
indentées `version "…"` / `resolved "…"`. `_nameFromHeader()` gère les
scopes `@scope/pkg`, préfixes `@npm:`/`@patch:`, et en-têtes multi-spécifications.

**`_parseBerry` (yarn v2+)** : blocs `"pkg@npm:^1.0.0":` en syntaxe
YAML-like sans guillemets sur `version:`. Le bloc `__metadata:` est ignoré.

---

## `lib/maven_parser.dart` — Dépendances Maven

Parseur pur Dart pour `pom.xml`, par extraction XML légère par regex (aucune
bibliothèque XML dans les dépendances du projet).

**Pré-nettoyage** : les sections `<dependencyManagement>`, `<build>` et
`<plugin>` sont retirées du XML avant extraction, pour éviter de capter des
déclarations de version sans dépendance effective ou des plugins.

**Extraction** : pour chaque bloc `<dependency>…</dependency>`, extrait
`groupId`/`artifactId`/`version` par regex ; ignore les scopes `test` et
`system` ; stocke le nom comme `"groupId:artifactId"`.

**PURL** : le getter `WheelPackage.purl` reconstruit
`pkg:maven/<groupId>/<artifactId>@<version>` en séparant le nom sur `:`.

---

## `lib/sbom_diff.dart` — Comparaison de SBOM (sous-commande `diff`)

### `SbomDiffer`

| Méthode | Entrée | Sortie |
|---|---|---|
| `diff(Map a, Map b)` | Deux SBOM CycloneDX ou SPDX (2.x/3.0) JSON parsés | `SbomDiffResult` |
| `printDiff(result)` | `SbomDiffResult` | Sortie ANSI colorée (vert=ajout, rouge=suppression, jaune=mise à jour) |
| `toJson(result)` | `SbomDiffResult` | `Map<String, dynamic>` avec section `summary` |
| `loadFile(path)` | Chemin fichier | `Future<Map<String, dynamic>>` (méthode statique — les trois autres sont des méthodes d'instance) |

```dart
class SbomDiffResult {
  final List<SbomComponent> added;
  final List<SbomComponent> removed;
  final List<SbomComponentUpdate> updated;  // suit uniquement le changement de version
}
```

**Algorithme** : `_indexComponents()` dispatche vers `_indexCycloneDxComponents`
(clé `components[]`), `_indexSpdxComponents` (`spdxVersion` présent, clé
`packages[]`) ou `_indexSpdx3Components` (`@graph` présent, nodes de type
`software_Package`), puis indexe chaque composant par `_componentKey()` =
`purl` sans le segment `@version` si présent, sinon `name:type`. Comparaison
des deux index : absent de A = ajout, absent de B = suppression, présent des
deux côtés avec version différente = mise à jour. Résultat trié par nom. Les
deux fichiers comparés peuvent être dans des formats différents (ex. l'un en
CycloneDX, l'autre en SPDX 3.0) — seule l'identité du composant (`purl`/nom)
compte, pas le format d'origine.

---

## `lib/sbom_merger.dart` — Fusion de SBOM (sous-commande `merge`)

```dart
class SbomMerger {
  Map<String, dynamic> merge(List<Map<String, dynamic>> sboms, {String? documentName});
}
```

`merge()` (méthode d'instance, pas statique) dispatche vers `_mergeCycloneDx`
ou `_mergeSpdx` selon que le premier SBOM fourni contient `spdxVersion`. Le
format de sortie suit toujours celui du **premier** fichier.

**`_mergeCycloneDx`** :
1. Le premier SBOM sert de base (préserve `metadata`).
2. Pour chaque SBOM suivant : déduplication des `components` par `purl`
   (puis par `bom-ref` si PURL absent), déduplication des `dependencies` par
   `ref`, des `citations` et de `definitions.patents` (CycloneDX 1.7) par
   `bom-ref`.
3. Nouveau `serialNumber` (UUID v4) généré pour le document fusionné.
4. `documentName` écrase `metadata.component.name` si fourni.

**`_mergeSpdx`** : même principe pour SPDX 2.3 — déduplication des
`packages[]` par `purl` puis `SPDXID`, des `relationships[]` par triple clé
(`spdxElementId`, `relationshipType`, `relatedSpdxElement`), nouveau document
SPDX 2.3 reconstruit.

SPDX 3.0 (JSON-LD) n'est pas supporté en entrée pour `merge` (seul `diff` le
lit) ; tous les fichiers source doivent être dans le même format que le
premier fourni — un format différent n'est pas détecté comme erreur mais
produit une fusion incomplète.

---

## `lib/sbom_reader.dart` — Lecteur SBOM (sous-commande `convert`)

Relit un fichier SBOM JSON existant et reconstruit une `List<Package>`.

```dart
enum SbomFormat { cyclonedx, spdx2, spdx3, unknown }

static SbomFormat detectFormat(Map<String, dynamic> json) {
  if (json['bomFormat'] == 'CycloneDX')    return SbomFormat.cyclonedx;
  if (json.containsKey('spdxVersion'))     return SbomFormat.spdx2;
  if (json.containsKey('@context') && json.containsKey('@graph'))
                                           return SbomFormat.spdx3;
  return SbomFormat.unknown;
}
```

`read(json)` dispatche selon le format : CycloneDX lit `components[]`, SPDX
2.3 lit `packages[]`, SPDX 3.0 filtre les nodes `@graph` de type
`software_Package`. Chaque extracteur renseigne `name`, `version`, `purl`,
`license`, `vendor`, `url`, `sha256` (si présent), et infère `packageType`
via `_purlToType(purl)` (préfixe `pkg:rpm/`, `pkg:golang/`, `pkg:npm/`,
`pkg:maven/`, `pkg:pypi/`, `pkg:cargo/`, `pkg:apk/`, `pkg:deb/`, sinon `'source'`).

---

## `lib/license_report_generator.dart` — Rapport de licences (sous-commande `licenses`)

```dart
class LicenseReportGenerator {
  Future<void> writeToFile(List<Package> packages, String outputPath, {String? documentName});
}
```

Regroupe les paquets par `pkg.license` **exacte** (clé = chaîne telle que
présente dans le SBOM source, y compris les expressions composées `A AND B`
fréquentes sur les paquets Debian/RPM) et écrit un rapport AsciiDoc : résumé
chiffré, avertissement copyleft, section détaillée par licence, section des
paquets sans licence détectée.

`_classify(license)` : heuristique par sous-chaîne sur l'expression
(insensible à la casse) — `AGPL` ou `GPL` non précédé d'une lettre (regex
`(?<![A-Z])GPL`, pour ne pas confondre avec `LGPL`) → `strongCopyleft` ;
`LGPL`/`MPL`/`EPL`/`CDDL`/`CPL`/`EUPL` → `weakCopyleft` ; sinon `permissive`
(ou `unknown` si la chaîne est vide). Cette classification s'applique sur
l'expression **entière**, donc une expression composée contenant un seul
token copyleft (ex. `BSD-3-Clause AND GPL-2.0-only AND MIT`) classe tout le
groupe en copyleft.

`_copyleftTokens(license, target)` : découpe une expression composée sur
`AND`/`OR` et ne retient que les tokens dont la classification individuelle
correspond à `target`. Utilisé uniquement pour la liste d'avertissement en
tête de rapport — le regroupement par section, lui, garde l'expression
complète telle que déclarée. Sans cette étape, un SBOM Debian réel (licences
systématiquement concaténées) produit un avertissement listant des dizaines
de chaînes composées illisibles plutôt que les identifiants copyleft
individuels concernés.

---

## `lib/policy_checker.dart` — Contrôle de politiques CI/CD

| Méthode | Paramètres | Retour |
|---|---|---|
| `checkDenyLicenses` | `List<Package> packages, List<String> denyPatterns` | `List<LicenseViolation>` |
| `runSbomqs` | `String sbomPath` | `Future<double?>` — score ou `null` si `sbomqs` absent |

`_licenseMatches(license, pattern)` : correspondance exacte (insensible à la
casse) ou correspondance partielle (`license.contains(pattern)`) — donc
`--deny-license GPL` bloque `GPL-2.0-only`, `GPL-3.0-or-later`,
`LGPL-2.1-only`, etc.

**Intégration CLI** : après génération, si des options politiques sont
présentes, `checkDenyLicenses` puis (si `--min-quality-score`) `runSbomqs`
sont appelés ; en cas de violation le détail est imprimé sur `stderr` et le
processus quitte avec le code **2** (distinct de `1` = erreur d'analyse).

---

## `lib/csv_generator.dart` — Export CSV

Génère un fichier CSV (RFC 4180) à partir d'une `List<Package>`. En-tête
fixe : `name,version,architecture,license,type,purl,url,vendor`. Les paquets
sont triés par nom. Chaque cellule passe par `_cell()` : les valeurs
contenant une virgule, un guillemet ou un saut de ligne sont entourées de
guillemets doubles, et les guillemets internes sont doublés.

---

## `bin/sbom_generator.dart` — Point d'entrée

### Résolution de `--input` : fichier liste, archive unique, ou dossier

Trois branches mutuellement exclusives :

```dart
if (await FileSystemEntity.isDirectory(inputPath)) {
  // Scan récursif : tout fichier matché par _isSupportedPackageFile()
  // devient un packageRef, dans le même pipeline que s'il figurait dans
  // un fichier liste (y compris le pré-traitement manifestes/lockfiles).
} else if (_isSingleArchiveInput(inputPath)) {
  // .zip/.tar*/.whl/.deb/.rpm/.jar : utilisé tel quel comme unique packageRef.
} else {
  // Fichier liste classique : une référence par ligne.
}
```

`_isSupportedPackageFile()` est volontairement plus stricte que le fichier
liste pour les manifestes : elle exige un nom de fichier **exact**
(`requirements.txt`, `pom.xml`, `go.sum`, `go.mod`, `package-lock.json`,
`yarn.lock`) plutôt qu'une extension générique, pour éviter qu'un
`README.txt` traînant dans l'arborescence scannée soit pris à tort pour un
fichier de requirements. Le fichier liste, lui, continue d'accepter
n'importe quel `.txt` (hors `.whl`) via `_isRequirements()`.

`--input` devient **optionnel** dès lors que `--image` est fourni (au moins
une des deux sources est requise).

### Option `--image` / `-I` — analyse d'image de conteneur

Trois formats de référence acceptés :

| Format | Description | Exemple |
|---|---|---|
| Registre | Image Docker Hub ou registre privé | `nginx:latest`, `ubuntu@sha256:…` |
| Archive tar | Export `docker save` (`.tar`, `.tar.gz`, `.tgz`) | `/path/ubuntu.tar` |
| OCI layout | Répertoire contenant `index.json` | `/path/oci_dir/` |

L'outil OCI (`--oci-tool`, défaut `syft`) est vérifié au démarrage
(`<tool> --version`) ; son absence est une erreur fatale. Les paquets OCI et
les paquets de la liste `--input` (si fournie) sont fusionnés avant
déduplication.

### Option `--rpm-dir` / `-d`

Résout les noms RPM nus (sans `/` ni extension) vers des fichiers `.rpm`
locaux au lieu d'interroger la base des paquets installés. Indexation au
démarrage : `rpmExactIndex` (stem complet → chemin, résolution NEVRA exacte)
et `rpmNameIndex` (nom de paquet extrait par `^(.+?)-\d` → liste triée de
chemins, résolution par nom court, avertissement + premier alphabétique si
plusieurs correspondances). Fallback transparent sur `rpm -q` si aucune
correspondance locale.

### Option `--format` / `-f` — multi-format

Liste virgule-séparée de formats ; chaque format génère un fichier de sortie
distinct.

- **Format unique** (`-f cyclonedx`) : `--output` est utilisé tel quel.
- **Formats multiples** (`-f cyclonedx,spdx,markdown`) : `--output` est
  traité comme un **chemin de base**, l'extension appropriée étant ajoutée
  automatiquement.

| Format | Extension ajoutée |
|--------|------------------|
| `cyclonedx` | `.cdx.json` |
| `spdx` | `.spdx.json` |
| `spdx3` | `.spdx3.jsonld` |
| `json` | `.custom.json` |
| `markdown` | `.md` |
| `asciidoc` | `.adoc` |
| `html` | `.html` |
| `csv` | `.csv` |

La boucle de résolution de dépendances est sautée si **tous** les formats
demandés sont `markdown`, `asciidoc` ou `html` (formats tabulaires qui
n'exploitent pas cette information).

### Sous-commandes `diff`, `merge`, `convert`, `validate`, `licenses`

Routées avant le parsing principal des options :

```dart
if (arguments.first == 'diff')     { await _runDiff(arguments.sublist(1));     return; }
if (arguments.first == 'merge')    { await _runMerge(arguments.sublist(1));    return; }
if (arguments.first == 'convert')  { await _runConvert(arguments.sublist(1));  return; }
if (arguments.first == 'validate') { await _runValidate(arguments.sublist(1)); return; }
if (arguments.first == 'licenses') { await _runLicenses(arguments.sublist(1)); return; }
if (arguments.first == 'scan')     { await _runScan(arguments.sublist(1));     return; }
```

- **`_runDiff(args)`** : valide 2 arguments positionnels, charge les fichiers
  via `SbomDiffer.loadFile()`, appelle `SbomDiffer.diff()`, puis
  `printDiff()` (défaut, ANSI, `--no-color` pour désactiver) ou `toJson()`
  (si `--json` ou `--output`). Code retour : `0` sans changement, `1` sinon.
- **`_runMerge(args)`** : valide N ≥ 2 arguments positionnels + `-o
  <sortie>` (obligatoire), `-n <nom>` optionnel. `SbomMerger.merge()` détecte
  le format du premier fichier (`spdxVersion` présent → SPDX 2.3, sinon
  CycloneDX) et fusionne tous les fichiers suivants selon cette même
  structure ; le format de sortie suit celui du premier fichier. Un fichier
  dans un format différent n'est pas rejeté explicitement, il produit
  simplement une fusion incomplète (pas de validation croisée des formats).
- **`_runConvert(args)`** : `-i <source>` (obligatoire), `-f <formats>`
  (virgule-séparés, défaut `cyclonedx`), `-o <sortie>`, `-n <nom>`,
  `--cyclonedx-version`. Charge le JSON source via `SbomReader.loadJson()`,
  détecte le format, relit les paquets via `SbomReader().read(json)`, puis
  réutilise les mêmes générateurs que le pipeline de génération principal
  (aucune analyse de paquets n'est refaite).
- **`_runValidate(args)`** : arguments positionnels = fichiers à valider,
  `--strict` étend le contrôle aux champs recommandés (pas seulement
  obligatoires). Vérifie la présence des champs structurels attendus selon
  le format détecté (`bomFormat`/`specVersion` + `components[].name/type`
  pour CycloneDX ; `spdxVersion`/`SPDXID`/`name`/`dataLicense` +
  `packages[].SPDXID/name` pour SPDX 2.3 ; `@context`/`@graph` + présence
  d'un node `SpdxDocument` pour SPDX 3.0). Code retour : `0` si tous
  valides, `1` sinon (fichier introuvable ou JSON illisible compte comme
  invalide sans interrompre la vérification des autres fichiers).
- **`_runLicenses(args)`** : `-i <source>` (obligatoire), `-o <sortie>`
  (obligatoire), `-n <nom>` optionnel. Même chargement que `_runConvert`
  (`SbomReader.loadJson()` + `SbomReader().read(json)`), puis délègue tout le
  regroupement/formatage à `LicenseReportGenerator().writeToFile()`.

### Sous-commande `scan` — analyse de vulnérabilités

`_runScan(args)` interroge un ou plusieurs scanners externes sur un SBOM
déjà généré, avec filtrage temporel :

Options : `--sbom <fichier>` (obligatoire), `--scanner <grype|osv|trivy|all>`
(défaut `grype`), `--cve-after`/`--cve-before <AAAA-MM-JJ>`,
`--cve-date-field <published|modified|latest>` (défaut `published`),
`--include-undated` (inclut les CVE sans date, exclues par défaut dès qu'un
filtre de date est actif), `--format <text|sarif>` (défaut `text`),
`--output <fichier>` (fichier de sortie pour `--format sarif` ; sans cette
option, le SARIF est affiché sur stdout).

Architecture interne :

| Fonction | Rôle |
|---|---|
| `_runScan()` | Parse les arguments, orchestre les scanners demandés |
| `_runScanner()` | Dispatch vers `_runGrype()` / `_runOsv()` / `_runTrivy()` |
| `_runGrype()` / `_runOsv()` / `_runTrivy()` | Lance le scanner via `Process.run()` (capture `ProcessException` si le binaire est introuvable → message explicite, pas de crash), parse son JSON propre, retourne une liste normalisée `{id, severity, package, published, modified}` |
| `_filterByDate()` | Applique `after`/`before`/`includeUndated` sur le champ de date choisi |
| `_printScanResults()` | Trie par sévérité décroissante (Critical → Unknown) et affiche un tableau texte par scanner (`--format text`) |
| `_buildSarifReport()` | Construit un rapport SARIF 2.1.0 (un `run` par scanner interrogé, une `rule` par identifiant de vulnérabilité, `level` dérivé de la sévérité via `_sarifLevel()`) — `--format sarif` |

Code retour : `0` si aucune vulnérabilité dans la plage demandée (tous
scanners confondus), `1` si au moins une trouvée ou en cas d'erreur de
scanner (l'échec d'un scanner n'empêche pas les autres de s'exécuter).

### Options CI/CD

- **`--deny-license <motif>`** (répétable) : après génération,
  `PolicyChecker.checkDenyLicenses()` est appelé ; violations listées sur
  `stderr`, code retour `2` si au moins une.
- **`--min-quality-score <score>`** : `PolicyChecker.runSbomqs()` est appelé
  sur le premier fichier de sortie JSON généré ; code retour `2` si le score
  est inférieur au seuil. L'absence de `sbomqs` fait ignorer le contrôle
  (pas d'échec pour cette seule raison).
- **`--sign`** : après génération et vérification des politiques,
  `_signWithCosign(path)` est appelé pour chaque fichier SBOM généré
  (`cosign sign-blob --yes --bundle <path>.bundle <path>`) ; échec non
  fatal (avertissement) si `cosign` est absent.

### Option `--license-map` / `-l`

Fichier de substitution de licences : une ligne `nom_paquet:
SPDX-expression` par entrée, commentaires `#`. Parsé par
`_parseLicenseMap()` → `Map<String, String>`. Appliqué après la
déduplication via `_applyLicenseOverrides()` qui reconstruit les objets
package immuables (`RpmPackage`, `WheelPackage`, `DebPackage`, `OciPackage`)
avec la licence substituée.

### Rapport d'erreurs structuré

Les packages dont le parser retourne `null` sont tracés par référence (pas
seulement comptés). En fin de traitement, un rapport est émis sur `stderr` :

```
⚠  2 paquet(s) ignoré(s) :
   • openssl-libs
   • mypkg-1.0-1.el9.x86_64.rpm
```

### Option `--concurrency` / `-c`

Contrôle le nombre de tâches traitées simultanément (défaut `4`, `0` =
illimité) via une classe `_Semaphore` maison :

```dart
class _Semaphore {
  _Semaphore(int count) : _count = count;
  int _count;
  final _waiters = <Completer<void>>[];
  Future<void> acquire() async {
    if (_count > 0) { _count--; return; }
    final waiter = Completer<void>();
    _waiters.add(waiter);
    await waiter.future;
  }
  void release() {
    if (_waiters.isNotEmpty) _waiters.removeAt(0).complete();
    else _count++;
  }
}
```

> `Future.wait(List.generate(...))` préserve l'ordre : `rawResults[i]`
> correspond à `mainRefs[i]` — l'ordre du SBOM final suit l'ordre du fichier
> d'entrée malgré le traitement concurrent.

### Vérification des outils

Chaque outil externe n'est vérifié (`<tool> --version`) que si le type de
source correspondant est effectivement présent dans l'exécution en cours :
`syft`/`trivy`/`skopeo` si `--image`, `rpm` si au moins une référence
RPM-compatible, `python3` si `.whl`/tar/`.zip`, `dpkg-deb` si `.deb`,
`unzip` si `.jar`.

### Déduplication

```dart
final seenRefs = <String>{};
for (final pkg in packages) {
  if (seenRefs.add(pkg.bomRef)) uniquePackages.add(pkg);
}
```

`bomRef` est distinct par type : `pkg-<name>-…` (RPM), `pkg-pypi-<name>-…`
(Python), `pkg-src-<name>-…` (source), `pkg-deb-<name>-…` (Debian),
`pkg-maven-<name>-…` (Maven), `pkg-golang-<name>-…` (Go), `pkg-npm-<name>-…`
(npm), `pkg-oci-<type>-<name>-…` (OCI).

### `_printProgress()`

`\r` + `\x1B[K` (ANSI EL) pour écraser la ligne courante sans défiler. Barre
de 32 cellules `█`/`░`, compteur `current/total` et pourcentage.

---

## `lib/cyclonedx_generator.dart` — Générateur CycloneDX 1.6/1.7

```dart
Map<String, dynamic> generate(List<Package> packages, List<PackageDependency> dependencies, {
  String? documentName, String? author, String? organization,
  String specVersion = '1.6',              // '1.6' ou '1.7'
  String? tlp,                             // distributionConstraints.tlp (1.7)
  String? citationSource,                  // citations[] attributedTo (1.7)
  Map<String, PatentAssertion>? patentsByPackageName,  // patentAssertions (1.7)
  OsInfo? osInfo,                          // composant operating-system (--image)
})
```

### Support CycloneDX 1.7

Le schéma JSON 1.6 a `additionalProperties: false` partout : les champs
propres à 1.7 (`citations`, `definitions.patents`,
`components[].patentAssertions`, `metadata.distributionConstraints`) ne sont
donc **jamais émis** en 1.6, et `generate()` lève une `ArgumentError` si
`tlp`/`citationSource`/`patentsByPackageName` sont fournis sans
`specVersion: '1.7'`. `CycloneDxGenerator.supportedSpecVersions` et
`.validTlpClassifications` exposent les valeurs valides pour la CLI.

`PatentAssertion` (patentNumber, jurisdiction, legalStatus, assertionType)
est validée avant génération. Chaque brevet référencé est dédupliqué dans
`definitions.patents[]` par `bom-ref` ; le composant correspondant reçoit
une entrée `patentAssertions[]` pointant vers ce `bom-ref`.

La citation (`--image` + `--cyclonedx-version 1.7`) attribue `/components`
au `bom-ref` de l'outil OCI utilisé (`--oci-tool`), ajouté comme second
`tools.components[]` dans les métadonnées.

### Champ `group` (composants Maven)

`WheelPackage(packageType: 'maven')` stocke les coordonnées Maven sous la
forme `"groupId:artifactId"` dans `Package.name`. `_packageToComponent`
sépare ce `name` en deux champs CycloneDX dédiés — `group: groupId` et
`name: artifactId` — pour suivre la convention CycloneDX standard.
`Package.name` lui-même n'est pas modifié : les autres générateurs (SPDX,
Markdown, CSV…) continuent d'afficher `"groupId:artifactId"` tel quel.
Corollaire côté lecture : `sbom_reader.dart` recombine `group` + `name` dès
qu'un composant a `packageType == 'maven'` et un champ `group` non vide.

### Propriétés spécifiques par type (`_packageToComponent`)

`RpmPackage` → `rpm:arch`, `rpm:release`, `rpm:epoch`, `rpm:buildTime`,
`rpm:requires` × N. `WheelPackage` → `<ns>:platform`, `<ns>:requires` × N
(`ns` = `pypi` ou `source`). `DebPackage` → `deb:arch`, `deb:depends` × N.
Le CPE n'est généré que pour les `RpmPackage`.

### Normalisation des licences

Délégué à `LicenseNormalizer.toCycloneDxLicenses(pkg.license)`.

### Composant OS de base (`osInfo`, `--image`)

Quand `osInfo` (voir `OsInfo` dans `lib/oci_parser.dart`) est fourni,
`_buildOsComponent()` ajoute en tête de `components[]` un composant
`type: "operating-system"` (`name`, `version`, `description`, `cpe`)
distinct des paquets applicatifs — nécessaire pour que Trivy en mode
`trivy sbom` évalue aussi les CVE des paquets système (voir la section
`OsInfo` sous `lib/oci_parser.dart` plus haut). `osInfo` est `null` pour
toute génération sans `--image` (ou avec le backend skopeo).

---

## `lib/spdx_generator.dart` — Générateur SPDX 2.3

Signature : `List<Package>`, plus `osInfo` (`OsInfo?`, optionnel). Normalisation via
`LicenseNormalizer.toSpdxExpression()`. Annotation type-aware selon le type
concret de `Package` (RPM : `arch`/`epoch`/`release` ; Python/source :
`platform` ; Debian : `arch`).

Quand `osInfo` est fourni, `_osToSpdx()` ajoute un paquet
`primaryPackagePurpose: "OPERATING-SYSTEM"` (SPDXID préfixé
`SPDXRef-OperatingSystem-`, requis par Trivy — voir la section `OsInfo`
sous `lib/oci_parser.dart`) avec une relation `DESCRIBES` depuis
`SPDXRef-DOCUMENT`.

---

## `lib/spdx3_generator.dart` — Générateur SPDX 3.0 JSON-LD

Signature : `List<Package>`, plus `osInfo` (`OsInfo?`, optionnel). Même logique d'annotation que SPDX 2.3.
`_buildVendorElements` crée un nœud `Organization` par valeur unique de
`pkg.vendor` (fonctionne pour tous les types de paquet).

Quand `osInfo` est fourni, `_osToElement()` ajoute un élément
`software:Package` avec `software:primaryPurpose: "operatingSystem"`,
inclus dans `rootElement` du `SpdxDocument` et dans la relation `describes`.
Représentation correcte selon la spec SPDX 3.0, mais **Trivy ne sait pas
lire de SBOM SPDX 3.0 JSON-LD du tout** (`trivy sbom` échoue avec `SBOM
decode error: unknown scanning is not yet supported`, indépendamment de ce
composant) — limitation de Trivy, sans rapport avec `sbom_generator`.

---

## `lib/simple_json_generator.dart` — Générateur JSON personnalisé

Signature : `List<Package>`. Le champ `packageType` est inclus dans chaque
entrée. Les champs RPM-spécifiques (`release`, `epoch`, `buildTime`) sont
ajoutés conditionnellement selon le type concret.

---

## `lib/markdown_generator.dart` — Tableau Markdown

Signature : `List<Package>`. Génère un tableau trié alphabétiquement par
nom. La résolution des dépendances est sautée en amont pour ce format.
Affiche `(inconnue)` si `pkg.license` est vide.

---

## `lib/asciidoc_generator.dart` — Tableau AsciiDoc

Équivalent AsciiDoc de `MarkdownGenerator` : même tri, même colonnes
(Paquet/Version/Architecture/Licence). Le caractère `|` dans les valeurs est
échappé (`\|`) pour éviter toute ambiguïté avec les séparateurs de cellules
AsciiDoc.

---

## `lib/html_generator.dart` — Rapport HTML interactif

Produit un fichier **entièrement autonome** : CSS et JavaScript inline,
aucune dépendance externe ni réseau requis.

| Section | Contenu |
|---|---|
| En-tête | Titre, date de génération, nombre de composants |
| Cartes de statistiques | Total composants, écosystèmes, licences distinctes, composants sans licence |
| Graphiques (CSS pur) | Barres horizontales proportionnelles — top 10 écosystèmes et top 15 licences |
| Tableau filtrable | Recherche texte (nom/version/licence/PURL) + filtre par type, tri par colonne |

Le tri/filtrage est du JavaScript vanilla (`filterTable()`, `sortTable(col)`).
`_esc(String s)` échappe `&`, `<`, `>`, `"` pour une insertion HTML sûre.

---

## Flux de données — exemples concrets

### RPM : `bash` depuis un fichier .rpm

```
1. Détection : .rpm → RpmParser.parsePackage()
2. rpm -qp --queryformat '…' → "bash|5.1.8|6.el9|x86_64|(none)|GPL-3.0-or-later|…"
3. RpmPackage : bomRef="pkg-bash-5.1.8-6.el9-x86_64", purl="pkg:rpm/bash@5.1.8-6.el9?arch=x86_64"
4. LicenseNormalizer.toCycloneDxLicenses("GPL-3.0-or-later")
   → {"license": {"id": "GPL-3.0-or-later"}}
```

### Python wheel : `requests-2.28.2-py3-none-any.whl`

```
1. Détection : .whl → WheelParser.parseWheelFile()
2. python3 zipfile → requests-2.28.2.dist-info/METADATA
3. _parseRfc822() → {name: "requests", version: "2.28.2", license: "Apache-2.0", …}
4. WheelPackage : packageType='pypi', purl="pkg:pypi/requests@2.28.2"
```

### Archive générique : `mariadb-11.4.8-linux-systemd-x86_64.tar.gz`

```
1. Détection : .tar.gz → TarParser.parseTarFile()
2. python3 tarfile : pas de PKG-INFO → type='generic', COPYING trouvé
3. parseArchiveFilename() → name="mariadb", version="11.4.8", arch="x86_64"
4. identifyArchiveLicense(COPYING) → "GPL-2.0-only"
5. WheelPackage : packageType='source', purl="pkg:generic/mariadb@11.4.8"
```

### Paquet Debian : `libssl3_3.0.1-1_amd64.deb`

```
1. Détection : .deb → DebParser.parseDebFile()
2. dpkg-deb -f → control RFC 822
3. DebPackage : bomRef="pkg-deb-libssl3-3.0.1-1-amd64",
               purl="pkg:deb/libssl3@3.0.1-1?arch=amd64"
```

### Dépendance Maven : `pom.xml`

```
1. Détection : pom.xml → MavenParser.parsePomXml() (pré-expansion)
2. Extraction regex des blocs <dependency>, scope compile
3. WheelPackage : packageType='maven', name="org.slf4j:slf4j-api"
               purl="pkg:maven/org.slf4j/slf4j-api@2.0.7"
```

### Image OCI : `nginx:latest` via syft

```
1. Détection OCI : --image nginx:latest (OciRefType.registry)
2. Process.run('syft', ['nginx:latest', '--output', 'json'])
3. _parseSyft() parcourt artifacts[] :
   {name: "bash", version: "5.1.8", type: "rpm", purl: "pkg:rpm/rhel/bash@5.1.8",
    licenses: [{spdxExpression: "GPL-3.0-or-later"}], metadata: {Arch: "x86_64"}}
4. OciPackage(name="bash", version="5.1.8", packageType="rpm",
              purlOverride="pkg:rpm/rhel/bash@5.1.8", bomRef="pkg-oci-rpm-bash-5.1.8")
5. Résultats ajoutés à ociPackages → fusionnés dans packages avant déduplication
```

---

## Étendre le code

### Ajouter un nouveau format de sortie

1. Créer `lib/mon_format_generator.dart` :

```dart
import 'dart:io';
import 'models.dart';

class MonFormatGenerator {
  Future<void> writeToFile(
    List<Package> packages,
    List<PackageDependency> dependencies,
    String outputPath, {
    String? documentName,
  }) async {
    final buf = StringBuffer();
    // … construction du contenu …
    await File(outputPath).writeAsString(buf.toString());
  }
}
```

2. Dans `bin/sbom_generator.dart` : ajouter le format à `_validFormats`,
   l'extension à `_formatExtension()`, et le `case` correspondant dans les
   deux boucles de génération (génération principale + `convert`).

### Ajouter un nouveau type de paquet

1. Dans `lib/models.dart` : créer `class MonPackage extends Package { … }`
   (ou réutiliser `WheelPackage` avec un nouveau `packageType` si la forme
   des données est proche d'un écosystème déjà « léger »).
2. Créer `lib/mon_parser.dart` avec une méthode
   `Future<MonPackage?> parse(String path)` (ou `List<MonPackage>
   parseFile(path)` pour une source à cardinalité 1:N — voir le bloc de
   pré-expansion dans `main()`).
3. Dans `bin/sbom_generator.dart` : ajouter la détection d'extension/nom de
   fichier, le dispatch (boucle concurrente ou pré-expansion selon la
   cardinalité), et la vérification d'outil externe si nécessaire.
4. Dans chaque générateur : ajouter `else if (pkg is MonPackage) { … }` pour
   les propriétés spécifiques (facultatif si `WheelPackage` suffit).
5. Mettre à jour `_isSupportedPackageFile()` si le type doit être détectable
   lors d'un scan de dossier (`--input <dossier>`).

### Ajouter un nouveau scanner à la sous-commande `scan`

1. Ajouter son nom à `_validScanners`.
2. Créer `_runMonScanner()` : lance le binaire via `Process.run()`, parse le
   JSON en `List<Map<String, dynamic>>` normalisé
   (`{id, severity, package, published, modified}`).
3. Ajouter un `case` dans `_runScanner()`.

---

## Pièges et décisions de conception

1. **Séparateur `|` dans SUMMARY (RPM)** — `SUMMARY` peut contenir des `|`.
   Il est placé en dernier dans `_queryFormat` et les fragments ≥ index 11
   sont rejoints.
2. **Doublons de bomRef (RPM)** — même NEVRA dans plusieurs dépôts → même
   `bomRef` → interdit par CycloneDX. La déduplication dans `main()`
   supprime le deuxième exemplaire.
3. **`LicenseRef-*` dans CycloneDX** — `license.id` est validé contre la
   liste SPDX officielle par sbomqs ; `LicenseRef-*` n'en fait pas partie.
   Utiliser `{"license": {"name": "…"}}` à la place.
4. **Champ `acknowledgement` (CycloneDX 1.6.1)** — cause une erreur de
   validation dans le schéma embarqué de sbomqs. Ne pas l'utiliser.
5. **`_capabilityName` et les modules Python RPM** — `split(RegExp(r'[\s(]'))`
   tronquerait `python3dist(lxml)` en `python3dist`. Le split sur
   `\s+[<>=!]` préserve les parenthèses.
6. **Faux positif GPL → LGPL dans la détection de licence** — le texte
   GPL-2.0 mentionne « GNU Library General Public License » dans sa section
   « How to Apply ». La détection LGPL ne porte que sur les 300 premiers
   caractères (titre du document).
7. **Dépendances Python intra-liste** — fonctionne si les noms sont
   normalisés de manière cohérente (PEP 503) des deux côtés
   (`provides`/`Requires-Dist`).
8. **Requirements.txt et manifestes : cardinalité 1:N** — incompatible avec
   la boucle concurrente (`Future<Package?>`, 1 ref → 0 ou 1 résultat).
   Solution : pré-expansion avant la boucle (voir `requirements_parser.dart`).
9. **Champ `License` absent dans de nombreux `.deb`** — le standard Debian
   ne le rend pas obligatoire ; `DebPackage.license` vide est un
   comportement conforme (→ `NOASSERTION` en SPDX), non une erreur.
10. **Ordre préservé par `Future.wait(List.generate(...))`** — le résultat
    à l'index `i` correspond à l'entrée `i`, malgré le traitement concurrent.
11. **`sbom_diff` et `sbom_merger` comprennent CycloneDX et SPDX 2.3** (`diff`
    comprend en plus SPDX 3.0 JSON-LD) — `_indexComponents`/`merge()`
    détectent le format via `spdxVersion`/`@graph`, sinon supposent
    CycloneDX. Pour `merge`, le format de sortie suit le premier fichier
    fourni ; mélanger des formats dans les fichiers source n'est pas rejeté
    explicitement et produit une fusion incomplète (pas de validation
    croisée).
12. **Écart syft/skopeo sur les images OCI** — syft lit aussi `MANIFEST.MF`
    avec des heuristiques de groupId non standard, ce qui lui fait trouver
    quelques paquets Java de plus que skopeo sur la même image. Documenté,
    non corrigé.

---

## Conventions de code

| Élément | Convention | Exemple |
|---------|-----------|---------|
| Classes | `PascalCase` | `RpmParser`, `WheelPackage` |
| Méthodes/variables | `camelCase` | `buildDependencies`, `packageRef` |
| Constantes/méthodes privées | préfixe `_` | `_queryFormat`, `_hasValue` |
| Fonctions de bibliothèque | `_camelCase` | `_safeId`, `_normalizePyName` |

### `_hasValue(String s)`

Présente dans tous les générateurs :
```dart
bool _hasValue(String s) => s.isNotEmpty && s != '(none)';
```
RPM retourne `"(none)"` pour les champs vides.

### Pattern `generate()` + `writeToFile()`

Les générateurs JSON/JSON-LD exposent les deux méthodes (`generate()`
retourne une structure testable sans I/O). `MarkdownGenerator`,
`AsciidocGenerator`, `HtmlGenerator` et `CsvGenerator` n'exposent que
`writeToFile()` — leur sortie n'est pas une structure de données réutilisable.

---

## Tableau de correspondance : source → champs SBOM

| Source | CycloneDX 1.6 | SPDX 2.3 | SPDX 3.0 |
|--------|--------------|----------|----------|
| `pkg.name` | `name` | `name` | `name` |
| `pkg.fullVersion` | `version` | `versionInfo` | `software:packageVersion` |
| `pkg.purl` | `purl` | `externalRefs[purl]` | `externalIdentifier[purl]` |
| `pkg.license` | `licenses[id/expression/name]` | `licenseConcluded/Declared` | `concludedLicense/declaredLicense` |
| `pkg.vendor` | `supplier.name` + `publisher` | `supplier: "Organization: …"` | `suppliedBy` (URI org) |
| `pkg.url` | `externalReferences[website]` | `downloadLocation` | `software:downloadLocation` |
| `pkg.summary` | `description` | `summary` | `summary` |
| `pkg.sha256Header` | `hashes[SHA-256]` | — | — |
| **RPM** `release`, `epoch`, `arch`, `buildTime` | `properties[rpm:*]` | `annotations` | `annotation` |
| **RPM** `requires` × N | `properties[rpm:requires]` × N | — | — |
| **Python/Source** `arch` | `properties[pypi:/source:platform]` | `annotations` | `annotation` |
| **RPM** CPE calculé | `cpe` | — | — |
| **Debian** `arch` | `properties[deb:arch]` | `annotations` | `annotation` |
| **Debian** `requires` × N | `properties[deb:depends]` × N | — | — |
| **Maven** coordonnées | `group` + `name` | `name` = `groupId:artifactId` | `name` = `groupId:artifactId` |
| résolution requires/provides | `dependencies[].dependsOn` | `relationships[DEPENDS_ON]` | `Relationship[dependsOn]` |

---

## Performance et limites

### Coût de traitement par paquet

| Type | Appels subprocess | Temps estimé |
|------|------------------|-------------|
| RPM (installé ou fichier) | 3 × `rpm` en parallèle | ~15–50 ms |
| Wheel `.whl` | 1 × `python3` | ~20–50 ms |
| Archive tar/zip (sdist ou générique) | 1 × `python3` | ~20–80 ms |
| Paquet Debian `.deb` | 1 × `dpkg-deb` | ~5–20 ms |
| Archive `.jar` | 1–N × `unzip` | ~10–40 ms |
| Requirements.txt / go.sum / go.mod / package-lock.json / yarn.lock / pom.xml | 0 subprocess (pur Dart) | < 1 ms/paquet |
| Image OCI (`--image`) | 1 appel bloquant, hors boucle concurrente | de quelques secondes (registre local) à plusieurs dizaines de secondes (registre distant, image volumineuse) |

La boucle principale est parallélisée via `Future.wait()` +
`_Semaphore(--concurrency)`. Avec `--concurrency 4` (défaut) sur une grande
liste, le gain est ~4× par rapport à une boucle séquentielle.
`--concurrency 0` lance toutes les entrées simultanément.

### Limites connues

- **Pas de résolution transitive** : seules les dépendances entre paquets
  présents dans la liste sont incluses.
- **CPE approximatifs** : valides syntaxiquement, peuvent différer des
  entrées NVD officielles.
- **Licences archive/heuristiques** : détection depuis les fichiers
  LICENSE/COPYING basée sur des patterns textuels, non exhaustive.
- **Champ License absent dans les `.deb`** : `DebPackage.license` souvent
  vide, ce qui produit `NOASSERTION` dans SPDX.
- **Pas de vérification préalable d'existence des fichiers** : un chemin
  invalide fait échouer le subprocess correspondant, le paquet est compté
  comme échec.
- **`sbom_diff`/`sbom_merger` sans validation croisée de format** entre
  fichiers source (voir Pièges §11).
- **Écart syft/skopeo** sur les paquets Java d'une image OCI (voir Pièges §12).

---

## Tests

```bash
dart test                            # tous les tests
dart test test/unit/                 # tests unitaires seuls
dart test test/integration/          # tests d'intégration seuls
```

Au moment de la rédaction : **244 tests** au total (225 unitaires + 19
d'intégration, dont 6 sautées automatiquement dans un environnement sans
`rpm` installé ou sans les archives OCI de test — `keycloak_26.tar` n'est
pas versionné). Comptage vérifié via `dart test -r compact`.

Exécutés automatiquement par `.github/workflows/ci.yml` (`dart analyze
--fatal-infos` puis `dart test`) sur chaque push/pull request vers `main`.

### Suites unitaires (`test/unit/`)

| Fichier | Couverture |
|---------|-----------|
| `license_normalizer_test.dart` | `toSpdxExpression`, `toCycloneDxLicenses`, cas limites |
| `archive_helpers_test.dart` | `parseArchiveFilename` (archives réelles + edge cases), `identifyArchiveLicense` |
| `rpm_parser_test.dart` | `buildDependencies` sans subprocess |
| `requirements_parser_test.dart` | parsing RFC, PEP 503, extras, marqueurs, directives |
| `go_parser_test.dart` | `parseGoSum`, `parseGoMod`, dédoublonnage, erreurs |
| `npm_parser_test.dart` | lockfileVersion 1/2/3, licences liste/chaîne, PURLs |
| `yarn_parser_test.dart` | yarn v1 classique, yarn v2+ Berry, PURLs |
| `maven_parser_test.dart` | extraction, scope test/system, dependencyManagement, PURL |
| `jar_parser_test.dart` | identité propre, dépendances relocalisées (uber-jar), overrides Spring |
| `oci_parser_test.dart` | `OciParser.detectRefType` (registre, `.tar`, `.tar.gz`, `.tgz`), reconstruction version/PURL upstream (backend trivy), extraction OS de base + traduction de famille (`_syftDistroToOsInfo`/`_trivyMetadataToOsInfo`) |
| `csv_generator_test.dart` | en-têtes, tri, échappement RFC 4180 |
| `cyclonedx_generator_test.dart` | spec 1.6/1.7, TLP, citations, brevets, composant OS de base (`osInfo`) |
| `spdx_generator_test.dart` | enveloppe SPDX-2.3, paquets, licences, relations DESCRIBES/DEPENDS_ON, paquet OS de base (`osInfo`) |
| `spdx3_generator_test.dart` | enveloppe JSON-LD, paquets, Organization partagée, relations describes/dependsOn, élément OS de base (`osInfo`) |
| `policy_checker_test.dart` | correspondance de licences interdites |
| `sbom_reader_test.dart` | détection de format, relecture CycloneDX |
| `sbom_diff_test.dart` | clé purl/name:type, CycloneDX/SPDX 2.3/SPDX 3.0, comparaison inter-format |
| `sbom_merger_test.dart` | dédup CycloneDX (purl/bom-ref) et SPDX 2.3 (purl/SPDXID), fusion des relations |
| `license_report_generator_test.dart` | regroupement par licence, classification copyleft fort/faible, découpage des expressions composées, paquets sans licence |

### Suite d'intégration (`test/integration/`)

| Fichier | Couverture |
|---------|-----------|
| `tar_integration_test.dart` | `TarParser` sur archives réelles, `WheelParser` sur wheels, bomRefs uniques |
| `oci_skopeo_test.dart` | Backend skopeo (détection RPM db, extraction Java) — nécessite `rpm`/`skopeo` |
| `policy_checker_sbomqs_test.dart` | `PolicyChecker.runSbomqs` sur un SBOM réel — nécessite `sbomqs` |
| `input_directory_test.dart` | `--input <dossier>` : scan récursif, filtrage par type |

Les tests d'intégration nécessitant un outil ou un fichier absent se
sautent automatiquement plutôt que d'échouer (voir `dart test` ci-dessus).

---

## Checklist avant modification

- [ ] `dart analyze lib/ bin/ test/` passe sans erreur ni avertissement
- [ ] `dart format --output=none lib/ bin/` passe sans différence
- [ ] `dart test` — tous les tests verts (ou sautés proprement si outil absent)
- [ ] Test sur les archives 3PP d'exemple (`example/3PP/`) : nom, version,
      arch, licence corrects
- [ ] Test avec liste mixte RPM + `.whl` + `.tar.gz` + `.zip` + `.deb` +
      `.jar` + `requirements.txt` + `--image`
- [ ] Test avec manifestes Go (`go.sum`, `go.mod`), npm
      (`package-lock.json`), yarn (`yarn.lock`), Maven (`pom.xml`)
- [ ] Test des sous-commandes `diff`, `merge`, `convert`, `validate`,
      `licenses`, `scan`
- [ ] Si modification de `--rpm-dir` : vérifier résolution exacte (NEVRA),
      résolution par nom, avertissement multi-match, fallback `rpm -q`
- [ ] Le SBOM CycloneDX passe `sbom_schema_valid: 10.0` dans sbomqs
- [ ] Pas de `bom-ref` dupliqués dans la sortie CycloneDX
- [ ] Si modification de `LicenseNormalizer` : relancer
      `test/unit/license_normalizer_test.dart`
- [ ] Si modification de `identifyArchiveLicense` : vérifier que GPL-2.0
      (MariaDB COPYING) n'est pas détecté comme LGPL
- [ ] Si modification de `parseArchiveFilename` : vérifier les cas 3PP du
      tableau dans `archive_helpers_test.dart`
- [ ] Si modification de `_capabilityName` : vérifier
      `python3dist(lxml) >= 3.0` → `python3dist(lxml)`
- [ ] Si modification de `OciParser`/`--image`/`--oci-tool` : tester les
      trois backends (syft, trivy, skopeo) avec registre, tar et OCI layout ;
      si la détection d'OS (`OsInfo`) est touchée, revérifier avec
      `trivy sbom` sur le SBOM produit que la classe "os-pkgs" est bien
      détectée (pas seulement que le composant OS est présent dans le JSON)
- [ ] Si ajout d'un type de paquet : mettre à jour `models.dart`, tous les
      générateurs (`if (pkg is …)`), `bin/sbom_generator.dart` (dispatch +
      vérification d'outil) et ce document
- [ ] Si ajout d'un parseur de manifeste 1:N : l'ajouter au bloc de
      pré-expansion dans `main()` avec son helper `_isXxx()` — ne pas
      passer par la boucle concurrente

---

## Dépendances externes

| Package | Version | Rôle |
|---------|---------|------|
| `args` | `^2.4.2` | Parsing des arguments CLI |
| `test` *(dev)* | `^1.31.1` | Framework de tests unitaires et d'intégration |

Tout le reste : bibliothèque standard Dart (`dart:io`, `dart:convert`,
`dart:math`, `dart:async`). Aucune bibliothèque XML/YAML/ZIP tierce — le
parsing `pom.xml` est fait par regex, l'inspection des `.whl`/`.tar`/`.zip`
délègue à `python3` en sous-processus.

Outils système requis à l'exécution, selon les fonctionnalités utilisées :

| Outil | Requis pour |
|-------|------------|
| `rpm` | paquets RPM (installés ou fichiers `.rpm`) |
| `python3` (+ `zipfile`/`tarfile` stdlib) | wheels `.whl`, archives `.tar*` et `.zip` |
| `dpkg-deb` | paquets Debian `.deb` |
| `unzip` | archives `.jar` (via `--input`), et backend `skopeo` (`--oci-tool skopeo`) |
| `syft` | images OCI avec `--oci-tool syft` (défaut) |
| `trivy` | images OCI avec `--oci-tool trivy` ; scanner de vulnérabilités avec `scan --scanner trivy` |
| `skopeo` + `tar` | images OCI avec `--oci-tool skopeo` |
| `grype` | scanner de vulnérabilités avec `scan --scanner grype` (défaut) |
| `osv-scanner` | scanner de vulnérabilités avec `scan --scanner osv` |
| `sbomqs` | `--min-quality-score` |
| `cosign` | `--sign` |

---

## Compilation et déploiement

```bash
# Développement (JIT, compile à la volée)
dart run bin/sbom_generator.dart -i packages.txt

# Binaire natif autonome (AOT, ~30 s de compilation)
dart compile exe bin/sbom_generator.dart -o sbom_generator

# Tests
dart test                            # tous les tests
dart test test/unit/                 # unitaires seulement
dart test test/integration/          # intégration seulement

# Analyse statique
dart analyze

# Formatage
dart format lib/ bin/ test/
dart format --output=none lib/ bin/ test/   # mode CI (pas de modification)
```

Le script `scripts/build-dist.sh` automatise la compilation du CLI **et**
de la GUI Flutter associée, et produit une archive de distribution
(`dist/sbom_generator-<version>-linux-<arch>.tar.gz`), avec génération
optionnelle de paquets `.rpm` (`--rpm`, nécessite `rpmbuild`). Voir
`scripts/install.sh` / `scripts/uninstall.sh` pour l'installation.

L'archive embarque un SBOM CycloneDX (`sbom.cdx.json`) des dépendances
runtime de la GUI (fontconfig, mesa-libGL, gtk4, libsecret — alignées sur
les `Requires` du sous-paquet gui dans `scripts/sbom_generator.spec`),
auto-hébergement : généré avec le binaire `sbom-generator` tout juste
compilé par le script lui-même, pas une installation préalable. Avec
`--rpm`, un second SBOM des RPM effectivement construits est produit à
côté de l'archive (`dist/sbom_generator-<version>-linux-<arch>-rpms.cdx.json`
— ne peut pas être inclus dans l'archive elle-même, puisque les RPM sont
construits à partir de cette archive).
