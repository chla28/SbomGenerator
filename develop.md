# sbom_generator — Documentation développeur

Ce document explique le fonctionnement interne du code pour une prise en main rapide.

---

## Architecture générale

Le programme suit un pipeline concurrent :

```
Fichier d'entrée (.txt)
        │
        ├─ lignes .txt ──► RequirementsParser (pur Dart, pré-expansion)
        │
        ▼
┌────────────────────────────────────────────┐
│  bin/sbom_generator.dart                   │  1. Lecture + validation CLI
│  (main + _Semaphore + _printProgress)      │  2. Détection du type par extension
│                                            │  3. Dispatch concurrent (--concurrency N)
│                                            │  4. Déduplication par bomRef
└──┬──────┬──────┬──────┬──────┬─────────────┘
   │      │      │      │      │
   ▼      ▼      ▼      ▼      ▼
  Rpm   Wheel   Tar   Zip   Deb
Parser Parser Parser Parser Parser
               └──┬───┘
                  ▼
          archive_helpers.dart
    (parseArchiveFilename, identifyArchiveLicense)

              │  List<Package>  (RpmPackage | WheelPackage | DebPackage)
              ▼
   RpmParser.buildDependencies()
              │  List<PackageDependency>
              ▼
       LicenseNormalizer ◄─── importé par tous les générateurs
              │
              ▼
┌─────────────────────────────────────────────┐
│  cyclonedx_generator.dart                   │
│  spdx_generator.dart              (choix    │
│  spdx3_generator.dart              selon -f)│
│  simple_json_generator.dart                 │
│  markdown_generator.dart                    │
└─────────────────────────────────────────────┘
              │
              ▼
   Fichier SBOM (.json / .jsonld / .md)
```

Tous les générateurs travaillent sur `List<Package>` — la classe abstraite commune à `RpmPackage`, `WheelPackage` et `DebPackage`.

---

## `lib/models.dart` — Hiérarchie de types

### Classe abstraite `Package`

Interface commune à tous les types de paquets. Tous les générateurs et `buildDependencies` travaillent exclusivement avec cette interface.

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
  String get packageType;   // 'rpm' | 'pypi' | 'source' | 'deb'
}
```

La fonction utilitaire de bibliothèque `_safeId(String s)` remplace tout caractère hors `[a-zA-Z0-9._-]` par `-`. Elle est utilisée dans les implémentations de `bomRef` et `spdxId`.

### `RpmPackage extends Package`

Représente un paquet RPM après interrogation. Champs supplémentaires (RPM-spécifiques) :

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

> **Piège :** Le `bomRef` inclut version ET release. Deux fichiers `.rpm` du même paquet depuis des dépôts différents produisent le même `bomRef`. La déduplication dans `main()` gère ce cas.

### `WheelPackage extends Package`

Représente un paquet Python (wheel) ou une archive source. Le comportement dépend de `packageType` :

| `packageType` | Source | PURL | bomRef prefix | spdxId prefix |
|---------------|--------|------|---------------|---------------|
| `'pypi'` | wheel `.whl` ou Python sdist (PKG-INFO présent) | `pkg:pypi/<name>@<ver>` | `pkg-pypi-` | `SPDXRef-pypi-` |
| `'source'` | archive générique sans métadonnées Python | `pkg:generic/<name>@<ver>` | `pkg-src-` | `SPDXRef-src-` |

Le nom Python est normalisé selon PEP 503 dans le PURL (`_normalizePyName` : minuscules, `[-_.]+ → -`).

Le champ `arch` contient le platform tag du wheel (ex. `any`, `linux_x86_64`) ou l'architecture détectée depuis le nom de fichier pour les archives génériques.

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

### `PackageDependency`

Structure simple liant un `bomRef` source à la liste des `bomRef` cibles dont il dépend.

```dart
class PackageDependency {
  final String sourceRef;      // bomRef du paquet source
  final List<String> dependsOn; // liste de bomRef des dépendances
}
```

### `generateUuidV4()`

Fonction libre générant un UUID v4 RFC 4122 via `Random.secure()`. Utilisée dans tous les générateurs pour `serialNumber` / `documentNamespace`.

---

## `lib/rpm_parser.dart` — Interrogation RPM

### Constante `_queryFormat`

```dart
static const _queryFormat =
    r'%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{EPOCH}|%{LICENSE}|%{VENDOR}|%{URL}|%{BUILDTIME}|%{SHA256HEADER}|%{SOURCERPM}|%{SUMMARY}\n';
```

`SUMMARY` est en dernier car il peut contenir des `|`. Le parser rejoint tous les fragments ≥ index 11 en cas de split excédentaire.

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

### `_parseCapabilities(ProcessResult result)` *(nouveau)*

Méthode synchrone remplaçant l'ancien `_queryCapabilities` asynchrone. Prend un `ProcessResult` déjà disponible et retourne `List<String>` (vide si `exitCode != 0`).

### `buildDependencies(List<Package> packages)`

Accepte une liste mixte RPM + Python. L'algorithme fonctionne en deux passes :

**Passe 1 — construction de `providesMap`**

```
providesMap : capability name → bomRef
```

Pour chaque paquet : le `name` du paquet + chaque entrée de `provides` sont ajoutés. Les paquets Python incluent leur nom normalisé dans `provides`, ce qui permet la résolution intra-Python.

**Passe 2 — résolution des `requires`**

Chaque entrée de `requires` est normalisée via `_capabilityName()` puis cherchée dans `providesMap`. Une dépendance n'est ajoutée que si la cible est dans la liste (`knownRefs`).

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
| `requests` (Python, déjà normalisé) | `requests` |

---

## `lib/wheel_parser.dart` — Lecture des wheels Python

### Fonctionnement

Le wheel est un ZIP contenant un répertoire `{name}-{version}.dist-info/METADATA`. La classe utilise `python3 zipfile` pour extraire ce fichier sans dézipper l'archive entière.

```python
z = zipfile.ZipFile(sys.argv[1])
name = next(x for x in z.namelist() if x.endswith('/METADATA'))
sys.stdout.buffer.write(z.read(name))
```

### `parseWheelFile(String path)`

Appelle python3, récupère le texte METADATA, délègue à `_buildPackage()`.

### `parseMetadataText(String sourceRef, String text, {String packageType})`

**Point d'extension public** utilisé par `TarParser` pour réutiliser le parseur RFC 822 sans dupliquer le code. Permet de construire un `WheelPackage` depuis un texte déjà extrait.

### Parsing RFC 822 (`_parseRfc822`)

Retourne `Map<String, List<String>>` : clé en minuscules → liste de valeurs. Les lignes de continuation (indent) sont concaténées.

### Extraction des champs clés

| Champ METADATA | Priorité | Fallback |
|---------------|----------|---------|
| License | `License-Expression` (PEP 639) | `License` → classifiers `License :: OSI Approved :: …` |
| URL | `Project-URL: Homepage, …` | `Home-page` |
| Vendor | `Author-email` (strip `<addr>`) | `Author` → `Maintainer` |
| Arch | dernier segment `-` avant `.whl` | `any` |
| Requires | `Requires-Dist` (strip contraintes et markers) | — |

### Normalisation des `Requires-Dist`

```dart
// "requests (>=2.0) ; extra == 'test'" → "requests"
var s = req.split(';').first.trim();
s = s.split(RegExp(r'[\s(]')).first.trim();
return _normalizePyName(s);  // lowercase + [-_.]+ → -
```

### Résolution de dépendances Python

`WheelPackage.provides = [normalizedName]` (nom normalisé PEP 503). `buildDependencies` ajoute aussi `pkg.name` à `providesMap`, couvrant à la fois le nom brut et le nom normalisé.

---

## `lib/tar_parser.dart` — Lecture des archives tar

### Script Python embarqué

Le script est exécuté via `python3 -c` et retourne un objet JSON sur stdout :

```json
{"type": "python", "content": "<texte RFC 822>"}
```
ou
```json
{"type": "generic", "licenseFile": "LICENSE", "license": "<2 KB du fichier>"}
```

**Logique de détection** (dans cet ordre) :
1. Cherche `*.dist-info/METADATA` ou `**/PKG-INFO` → type `python`
2. Cherche `LICENSE`, `COPYING`, `LICENSE-*`, `LICENCE`, `COPYING.*` à profondeur ≤ 2 → type `generic` avec le contenu du premier fichier trouvé (trié par profondeur puis longueur)

### Cas Python sdist

Si `type == 'python'` : délègue à `WheelParser().parseMetadataText(path, content)` → retourne un `WheelPackage` avec `packageType='pypi'`.

### Cas archive générique

Si `type == 'generic'` : délègue à `buildGenericArchivePackage()` (depuis `archive_helpers.dart`) :
1. Analyse le nom de fichier via `parseArchiveFilename()`
2. Identifie la licence via `identifyArchiveLicense()`
3. Retourne un `WheelPackage` avec `packageType='source'`

> Ces fonctions sont désormais dans `lib/archive_helpers.dart` (partagées avec `ZipParser`). La logique est identique à l'ancienne implémentation privée de `TarParser`.

### Parsing du nom de fichier (`parseArchiveFilename` dans archive_helpers)

**Algorithme :**

1. Supprimer l'extension (`.tar.gz`, `.tgz`, `.tar`)
2. Découper sur `-`
3. Trouver l'index du premier segment correspondant à `^\d+\.\d+` (version sémantique)
4. **Nom** = segments avant la version, moins les mots-clés plateforme
5. **Version** = le segment version
6. **Arch** = premier segment reconnu comme architecture

**Mots-clés filtrés du nom** (`_isPlatformSegment`) :
- OS : `linux`, `windows`, `darwin`, `macos`, `win`, `osx`
- Arch : `x86_64`, `x64`, `amd64`, `arm64`, `aarch64`, `i386`, `i686`
- Divers : `systemd`, `community`, `enterprise`
- Distros (regex) : `rhel8`, `rhel88`, `el9`, `fc40`, `centos7`, `ubuntu22`, …

**Résultats sur les archives 3PP :**

| Fichier | nom | version | arch |
|---------|-----|---------|------|
| `apache-tomcat-10.1.44.tar.gz` | `apache-tomcat` | `10.1.44` | `any` |
| `mariadb-11.4.8-linux-systemd-x86_64.tar.gz` | `mariadb` | `11.4.8` | `x86_64` |
| `mongodb-linux-x86_64-rhel8-8.0.12.tgz` | `mongodb` | `8.0.12` | `x86_64` |
| `mongodb-database-tools-rhel88-x86_64-100.13.0.tgz` | `mongodb-database-tools` | `100.13.0` | `x86_64` |
| `mongosh-2.5.6-linux-x64.tgz` | `mongosh` | `2.5.6` | `x86_64` |

### Identification de licence (`identifyArchiveLicense` dans archive_helpers)

Travaille sur les 2 000 premiers caractères du fichier de licence. Utilise deux zones :

- **`title`** (300 premiers chars) pour les familles GPL/LGPL — évite le faux positif : GPL-2.0 mentionne « GNU Library General Public License » dans son corps, mais pas dans son titre.
- **`lower`** (2 000 chars) pour Apache, MIT, SSPL, MPL, etc.

Licences reconnues : `SSPL-1.0`, `Apache-2.0`, `Apache-1.1`, `GPL-2.0-only`, `GPL-3.0-only`, `LGPL-2.0-only`, `LGPL-2.1-only`, `LGPL-3.0-only`, `MPL-2.0`, `MPL-1.1`, `MIT`, `ISC`, `BSD-2-Clause`, `BSD-3-Clause`, `EPL-2.0`, `EPL-1.0`, `CDDL-1.0`.

> **Piège :** Le texte GPL-2.0 contient « use the GNU Library General Public License instead » dans la section « How to Apply ». Vérifier uniquement le titre (300 premiers chars) empêche ce faux positif LGPL.

---

## `lib/license_normalizer.dart` — Normalisation SPDX centralisée

Factorisation de la logique de normalisation des licences qui était auparavant enfouie dans `cyclonedx_generator.dart`. Désormais importé par les trois générateurs (CycloneDX 1.6, SPDX 2.3, SPDX 3.0).

### `LicenseNormalizer` (classe, méthodes toutes `static`)

| Méthode | Retour | Usage |
|---------|--------|-------|
| `toSpdxExpression(String raw)` | `String` | Expression SPDX pour SPDX 2.3 / 3.0 |
| `toCycloneDxLicenses(String raw)` | `List<Map<String, dynamic>>` | Structure `licenses[]` CycloneDX 1.6 |

### Algorithme commun

1. Cas vide / `(none)` → retourne vide
2. Normalisation des opérateurs booléens (`and` → `AND`, `or` → `OR`, `with` → `WITH`) avec regex lookbehind/lookahead `\S` pour protéger les tokens collés (`GPL-2.0-or-later` non altéré)
3. Détection d'expression composée (présence de `AND`/`OR`/`WITH` entourés d'espaces)
4. Résolution token par token dans `_sortedEntries` (tri longueur décroissante → évite les matches courts avant les longs)
5. Choix du champ CycloneDX : `expression` (composé), `id` (SPDX versionné ou `LicenseRef-*`), `name` (inconnu sans numéro)

> **Optimisation :** `_sortedEntries` est `static final` — calculé une seule fois au chargement de la classe. L'ancien code retriait la table à chaque appel de `_normaliseExpressionTokens`.

---

## `lib/archive_helpers.dart` — Helpers partagés archives

Code partagé entre `TarParser` et `ZipParser` pour éviter la duplication de ~120 lignes.

### Exports (fonctions et classe niveau bibliothèque)

| Symbole | Description |
|---------|-------------|
| `class ArchiveFilenameInfo` | `{String name, version, arch}` — résultat du parsing de nom de fichier |
| `parseArchiveFilename(String path)` | Analyse nom/version/arch depuis le nom de fichier (extensions `.tar.gz`, `.tgz`, `.tar`, `.zip`) |
| `identifyArchiveLicense(String text)` | Heuristique SPDX depuis ≤ 2 000 chars du fichier licence — même algorithme que l'ancienne `_identifyLicense` de TarParser |
| `buildGenericArchivePackage(String path, {...})` | Construit un `WheelPackage(packageType='source')` depuis les infos de filename + licence |

> Ces fonctions sont package-level (sans préfixe `_`) pour être accessibles depuis `tar_parser.dart` et `zip_parser.dart` tout en restant internes au package.

---

## `lib/zip_parser.dart` — Lecture des archives ZIP génériques

Même logique que `TarParser` mais pour les fichiers `.zip`. Utilise `python3 zipfile` au lieu de `tarfile`.

### `ZipParser`

```dart
class ZipParser {
  final _wheelParser = WheelParser();
  Future<Package?> parseZipFile(String path) async { … }
}
```

### Script Python embarqué

Le script utilise `zipfile.ZipFile` pour inspecter le contenu sans extraction complète :

1. Cherche `*.dist-info/METADATA` ou `PKG-INFO` → `{"type": "python", "content": "…"}`
2. Cherche un fichier `LICENSE`/`COPYING` à profondeur ≤ 2 → `{"type": "generic", "licenseFile": "…", "license": "…"}`
3. Ni l'un ni l'autre → `{"type": "generic", "licenseFile": "", "license": ""}`

### Dispatch Python sdist vs générique

Identique à `TarParser` : `type == 'python'` → `WheelParser.parseMetadataText()`, `type == 'generic'` → `buildGenericArchivePackage()`.

---

## `lib/deb_parser.dart` — Lecture des paquets Debian

### `DebParser`

```dart
class DebParser {
  Future<DebPackage?> parseDebFile(String path) async { … }
  Map<String, String> _parseControl(String text) { … }
  List<String> _parseDependsList(String depends) { … }
}
```

### Extraction

```bash
dpkg-deb -f /opt/pkgs/libssl3_3.0.1_amd64.deb
```

Retourne le contenu du fichier `DEBIAN/control` en RFC 822. Champs lus :

| Champ control | Champ `DebPackage` | Notes |
|--------------|-------------------|-------|
| `Package` | `name` | |
| `Version` | `version` | |
| `Architecture` | `arch` | |
| `License` / `X-License` | `license` | absent de nombreux .deb |
| `Maintainer` | `vendor` | |
| `Homepage` | `url` | |
| `Description` | `summary` | première ligne seulement |
| `Depends`, `Pre-Depends` | `requires` | split virgule puis pipe |
| `Provides` | `provides` | |

### `_parseDependsList`

Découpe sur `,` puis sur `|` (alternatives), retire les contraintes de version `(>= …)`, normalise les espaces. Exemple : `"libc6 (>= 2.17) | libc6-amd64"` → `["libc6", "libc6-amd64"]`.

---

## `lib/jar_parser.dart` — Coordonnées Maven d'un `.jar` autonome

Contrairement à `MavenParser` (qui lit un manifeste `pom.xml`), `JarParser` extrait les
coordonnées Maven directement d'une archive `.jar` binaire, en miroir de la logique déjà
utilisée pour le scan d'images OCI dans `oci_parser.dart` (`_parseMavenJars`), mais
retourne un `WheelPackage(packageType: 'maven')` (comme `maven_parser.dart`) plutôt qu'un
`OciPackage` — pas de notion d'`imageRef` pour un fichier local.

### `JarParser`

```dart
class JarParser {
  Future<WheelPackage?> parseJarFile(String path) async { … }
  Future<(String, String, String)?> _fromPomProperties(String path) async { … }
  Future<String?> _groupIdFromManifest(String path) async { … }
  bool _looksLikeGroupId(String s) => s.contains('.') && s == s.toLowerCase() && !s.contains(' ');
}
```

### Chaîne de fallback

1. `unzip -p <jar> "META-INF/maven/*/*/pom.properties"` — parsing clé=valeur
   (`groupId`, `artifactId`, `version`). En cas d'archive avec plusieurs
   `pom.properties` embarqués (jar « shaded »/uber-jar), les valeurs sont
   simplement écrasées ligne à ligne (dernier match gagnant) : pas de gestion
   de plusieurs artefacts par jar dans ce cas — cas jugé hors scope pour un
   `.jar` passé individuellement en `--input`.
2. À défaut, convention de nom de fichier `<groupId>.<artifactId>-<version>.jar`
   (Quarkus/Red Hat) : regex `-(\d)` pour repérer le début de version, puis
   dernier `.` du préfixe pour séparer groupId/artifactId.
3. À défaut (préfixe sans point — la très grande majorité des jars réels,
   convention `<artifactId>-<version>.jar` simple), lecture de
   `META-INF/MANIFEST.MF` à la recherche d'un groupId plausible, dans cet
   ordre de priorité : `Bundle-SymbolicName`, `Implementation-Vendor-Id`,
   `Implementation-Title`, `Automatic-Module-Name` (première occurrence de
   chaque clé conservée, repliement de ligne RFC 822 géré). Une valeur n'est
   retenue que si `_looksLikeGroupId` l'accepte : au moins un point, et
   entièrement en minuscules (rejette par ex. `javafx.baseEmpty`, une
   valeur `Automatic-Module-Name` qui n'est pas un vrai nom de package).
   **Découvert par comparaison avec syft sur un jeu réel de 207 jars** (voir
   commit associé) : ce comportement reproduit exactement syft pour la
   quasi-totalité des cas testés (ex. `caffeine` → `com.github.ben-manes.caffeine`
   via `Bundle-SymbolicName`, `commons-httpclient` → `org.apache` via
   `Implementation-Vendor-Id` prioritaire sur `Implementation-Title`).
4. Si le manifeste ne donne rien d'exploitable non plus, `groupId` reprend
   la valeur de `artifactId` (`pkg:maven/<artifactId>/<artifactId>@<version>`)
   — c'est dégradé mais **non abandonné** : mieux vaut un paquet avec un
   groupId approximatif qu'un paquet silencieusement absent du SBOM.
5. Seul un nom de fichier sans aucun suffixe `-<chiffre>` reconnaissable fait
   réellement échouer l'extraction (`null` + avertissement `stderr`) : ce
   cas est rare et reste hors scope (aucune donnée exploitable nulle part).

**Limite connue, assumée** : certaines bibliothèques très répandues
(Spring Framework notamment : `spring-core`, `spring-beans`, …) n'exposent
leur vrai groupId (`org.springframework`) nulle part dans le jar lui-même —
seul un `Automatic-Module-Name` du type `spring.core` est présent. syft
résout ce cas via une base de connaissance interne figée (mapping
artefact→groupId pour des bibliothèques ultra-connues), que nous ne
répliquons pas ici : notre sortie pour ces jars précis est donc
`pkg:maven/spring.core/spring-core@…` plutôt que
`pkg:maven/org.springframework/spring-core@…`. Le paquet est présent avec
la bonne version, seul le groupId diffère — jugé acceptable plutôt que
d'embarquer un dictionnaire de bibliothèques connues.

Requiert `unzip` dans le PATH (vérification dans `bin/sbom_generator.dart`,
`hasJar` → `unzip -v`).

---

## `lib/requirements_parser.dart` — Parsing requirements.txt Python

Parser **pur Dart**, sans subprocess. Retourne `List<WheelPackage>`.

### `RequirementsParser`

```dart
class RequirementsParser {
  List<WheelPackage> parseFile(String path) { … }
  WheelPackage? _parseLine(String raw, String sourceRef) { … }
}
```

### Lignes ignorées

- Vides ou commençant par `#`
- Directives pip : `-r`, `-i`, `-e`, `-f`, `-c`

### Extraction par ligne

1. Retire les marqueurs d'environnement (`;` et suite)
2. Retire les commentaires inline (`#` et suite)
3. Retire les extras `[security]` (regex `\[.*?\]`)
4. Extrait la version après `==` (épinglée) ou le premier nombre de version sinon
5. Normalise le nom selon PEP 503 (`[-_.]+ → -`, minuscules)

### Intégration dans `main()`

Les fichiers `.txt` sont **pré-expansés avant la boucle concurrente** :

```dart
for (final ref in inputRefs) {
  if (_isRequirements(ref)) {
    preloadedPackages.addAll(RequirementsParser().parseFile(ref));
  } else {
    mainRefs.add(ref);
  }
}
// … boucle Future.wait sur mainRefs …
packages.addAll(preloadedPackages);
```

> **Pourquoi pré-expansion ?** La boucle concurrente produit `Future<Package?>` (1 ref → 0 ou 1 paquet). Un requirements.txt peut contenir N paquets (cardinalité 1:N), incompatible avec ce modèle.

---

## `bin/sbom_generator.dart` — Point d'entrée

### Résolution de `--input` : fichier liste, archive unique, ou dossier

Trois branches mutuellement exclusives (voir le bloc « Read package list ») :

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

`_isSupportedPackageFile()` est volontairement plus stricte que le fichier liste pour les
manifestes : elle exige un nom de fichier **exact** (`requirements.txt`, `pom.xml`,
`go.sum`, `go.mod`, `package-lock.json`, `yarn.lock`) plutôt qu'une extension générique
(`*.txt` par ex.), pour éviter qu'un `README.txt` ou un `notes.txt` traînant dans
l'arborescence scannée soit pris à tort pour un fichier de requirements. Le fichier liste,
lui, continue d'accepter n'importe quel `.txt` (hors `.whl`) via `_isRequirements()` — la
tolérance y est acceptable car l'utilisateur a explicitement tapé le chemin.

Les noms de paquets RPM nus (ex. `bash`) ne sont jamais découverts par le scan de
dossier : ce ne sont pas des fichiers sur disque. `--rpm-dir` reste le mécanisme dédié
pour résoudre ce cas (voir ci-dessous).

`FileSystemEntity.type()` remplace l'ancien `File(inputPath).exists()` pour la
vérification d'existence initiale, car ce dernier renvoie `false` pour un chemin de
dossier (uniquement vrai pour les fichiers), ce qui aurait fait échouer `--input
<dossier>` avec « Input file not found ».

### Option `--rpm-dir` / `-d`

Permet de résoudre les noms RPM nus (sans `/` ni extension) vers des fichiers `.rpm` locaux au lieu d'interroger la base de données des paquets installés.

**Indexation au démarrage** (une seule fois) :

```dart
final rpmExactIndex = <String, String>{};   // stem → chemin absolu
final rpmNameIndex  = <String, List<String>>{}; // nom paquet → [chemins triés]

await for (final entity in dir.list(recursive: true, followLinks: false)) {
  if (entity is File && entity.path.endsWith('.rpm')) {
    final stem = entity.path.split('/').last.replaceAll(RegExp(r'\.rpm$'), '');
    rpmExactIndex[stem] = entity.path;
    final name = RegExp(r'^(.+?)-\d').firstMatch(stem)?.group(1) ?? stem;
    rpmNameIndex.putIfAbsent(name, () => []).add(entity.path);
  }
}
for (final paths in rpmNameIndex.values) paths.sort();
```

- **`rpmExactIndex`** : clé = stem complet (ex. `bash-5.1.8-6.el9.x86_64`), valeur = chemin. Couvre les correspondances NEVRA exactes dans le fichier d'entrée.
- **`rpmNameIndex`** : clé = nom de paquet extrait par `^(.+?)-\d` (ex. `bash`), valeur = liste triée de chemins. Couvre les noms courts.

**Résolution dans la boucle** :

```dart
if (rpmDir != null && !ref.contains('/') && !ref.endsWith('.whl') && !_isTar(ref)) {
  final resolved = rpmExactIndex[ref] ?? rpmNameIndex[ref]?.first;
  if (resolved != null) ref = resolved;
  // Si plusieurs fichiers correspondent au nom : avertissement + premier alphabétique
}
```

Si aucune correspondance n'est trouvée dans le dossier, `rpm -q` est utilisé normalement (fallback transparent).

Les références `.whl`, archives tar/zip, `.deb` et `.jar` ne sont jamais concernées, même si `--rpm-dir` est spécifié.

### Option `--format` / `-f` — multi-format *(nouveau)*

Accepte désormais une liste virgule-séparée de formats. Chaque format génère un fichier de sortie distinct.

- **Format unique** (`-f cyclonedx`) : `--output` est utilisé tel quel (compatibilité ascendante)
- **Formats multiples** (`-f cyclonedx,spdx,markdown`) : `--output` est traité comme un **chemin de base** ; l'extension appropriée est ajoutée automatiquement par `_formatExtension()` / `_basePath()`

| Format | Extension ajoutée |
|--------|------------------|
| `cyclonedx` | `.cdx.json` |
| `spdx` | `.spdx.json` |
| `spdx3` | `.spdx3.jsonld` |
| `json` | `.custom.json` |
| `markdown` | `.md` |

`_basePath(output)` retire les extensions connues du nom passé à `--output` avant d'ajouter la nouvelle extension. La validation des formats est faite manuellement (const `_validFormats`) puisque `ArgParser.allowed:` ne supporte pas les valeurs composites.

La boucle de résolution de dépendances est skippée seulement si **tous** les formats demandés sont `markdown`.

### Option `--license-map` / `-l` *(nouveau)*

Fichier de substitution de licences : une ligne `nom_paquet: SPDX-expression` par entrée, commentaires `#`.

Parsé par `_parseLicenseMap(String path)` → `Map<String, String>`. Appliqué après la déduplication via `_applyLicenseOverrides(packages, overrides)` qui reconstruit les objets package immuables (`RpmPackage`, `WheelPackage`, `DebPackage`) avec la licence substituée. Les paquets sans correspondance sont retournés inchangés.

```text
# Exemple overrides.txt
libssl3: Apache-2.0
mongodb: SSPL-1.0
```

### Rapport d'erreurs structuré *(nouveau)*

Les packages dont le parser retourne `null` sont désormais **tracés par ref** (pas seulement comptés). À la fin du traitement, un rapport est émis sur `stderr` :

```
⚠  2 paquet(s) ignoré(s) :
   • openssl-libs
   • mypkg-1.0-1.el9.x86_64.rpm
```

Implémentation : la boucle `Future.wait` utilise l'index `i` pour corréler `rawResults[i]` → `mainRefs[i]` dans `failedRefs`. Les messages d'erreur détaillés des parsers restent émis sur `stderr` au fil de l'eau.

### Option `--concurrency` / `-c` *(nouveau)*

Contrôle le nombre de tâches traitées simultanément (défaut : `4`, `0` = illimité). Implémenté via la classe `_Semaphore` :

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

La boucle principale est remplacée par :

```dart
final sem = _Semaphore(concurrencyN == 0 ? mainRefs.length : concurrencyN);
final rawResults = await Future.wait(
  List<Future<Package?>>.generate(mainRefs.length, (i) async {
    await sem.acquire();
    try {
      return await _processRef(mainRefs[i], …);
    } finally { sem.release(); }
  }),
);
```

> `Future.wait(List.generate(...))` préserve l'ordre : `rawResults[i]` correspond à `mainRefs[i]`.

### Pré-traitement requirements.txt (`_isRequirements`)

```dart
bool _isRequirements(String ref) => ref.endsWith('.txt') && !ref.endsWith('.whl');
```

Les lignes `.txt` sont extraites de la liste principale avant la boucle concurrente et pré-parsées par `RequirementsParser`. Leurs paquets sont accumulés dans `preloadedPackages` et ajoutés après la boucle.

### Dispatch par extension *(étendu)*

```dart
if (ref.endsWith('.whl')) {
  pkg = await whlParser.parseWheelFile(ref);
} else if (_isTar(ref)) {          // .tar | .tar.gz | .tgz
  pkg = await tarParser.parseTarFile(ref);
} else if (ref.endsWith('.zip')) {
  pkg = await zipParser.parseZipFile(ref);
} else if (ref.endsWith('.deb')) {
  pkg = await debParser.parseDebFile(ref);
} else {
  pkg = await rpmParser.parsePackage(ref);
}
```

### Vérification des outils

- `rpm` : vérifié si la liste contient au moins une référence non-`.whl`, non-tar, non-`.zip`, non-`.deb`
- `python3` : vérifié si la liste contient au moins un `.whl`, tar ou `.zip`
- `dpkg-deb` : vérifié si la liste contient au moins un `.deb`

### Déduplication

```dart
final seenRefs = <String>{};
for (final pkg in packages) {
  if (seenRefs.add(pkg.bomRef)) uniquePackages.add(pkg);
}
```

`bomRef` est distinct par type : `pkg-<name>-…` (RPM), `pkg-pypi-<name>-…` (Python), `pkg-src-<name>-…` (source).

### Résolution des dépendances

Skippée pour le format `markdown` (inutile et coûteuse).

### `_printProgress()`

`\r` + `\x1B[K` (ANSI EL) pour écraser la ligne courante sans défiler.

---

## `lib/cyclonedx_generator.dart` — Générateur CycloneDX 1.6/1.7

### Signature mise à jour

```dart
Map<String, dynamic> generate(List<Package> packages, List<PackageDependency> dependencies, {
  String? documentName, String? author, String? organization,
  String specVersion = '1.6',              // '1.6' ou '1.7'
  String? tlp,                             // distributionConstraints.tlp (1.7)
  String? citationSource,                  // citations[] attributedTo (1.7)
  Map<String, PatentAssertion>? patentsByPackageName,  // patentAssertions (1.7)
})
```

### Support CycloneDX 1.7

Le schéma JSON 1.6 a `additionalProperties: false` partout : les champs propres à 1.7
(`citations`, `definitions.patents`, `components[].patentAssertions`,
`metadata.distributionConstraints`) ne sont donc **jamais émis** en 1.6, et `generate()`
lève une `ArgumentError` si `tlp`/`citationSource`/`patentsByPackageName` sont fournis sans
`specVersion: '1.7'`. `CycloneDxGenerator.supportedSpecVersions` et
`.validTlpClassifications` exposent les valeurs valides pour la CLI.

`PatentAssertion` (patentNumber, jurisdiction, legalStatus, assertionType) est validée
avant génération (regex ST.3 pour `jurisdiction`, enums CycloneDX pour le reste). Chaque
brevet référencé est dédupliqué dans `definitions.patents[]` par `bom-ref`
(`patent-<numéro normalisé>`) ; le composant correspondant reçoit une entrée
`patentAssertions[]` pointant vers ce `bom-ref`. Point notable : le champ `asserter` doit
être désambiguïsé avec un `url: []` vide, sinon le schéma le valide simultanément comme
`organizationalEntity` **et** `organizationalContact` et le `oneOf` strict échoue.

La citation (`--image` + `--cyclonedx-version 1.7`) attribue `/components` au `bom-ref`
de l'outil OCI utilisé (`--oci-tool`), ajouté comme second `tools.components[]` dans les
métadonnées.

### Propriétés spécifiques par type (`_packageToComponent`)

```dart
if (pkg is RpmPackage) {
  // rpm:arch, rpm:release, rpm:epoch, rpm:buildTime, rpm:requires × N
} else if (pkg is WheelPackage) {
  final ns = pkg.packageType == 'pypi' ? 'pypi' : 'source';
  // <ns>:platform, <ns>:requires × N
}
```

Le CPE n'est généré que pour les `RpmPackage` (les CPE NVD concernent les distributions Linux).

### Propriétés spécifiques Debian (`_packageToComponent`)

```dart
} else if (pkg is DebPackage) {
  properties.add({'name': 'deb:arch', 'value': pkg.arch});
  for (final req in pkg.requires) {
    properties.add({'name': 'deb:depends', 'value': req});
  }
}
```

### Normalisation des licences

Délégué à `LicenseNormalizer.toCycloneDxLicenses(pkg.license)` (depuis `lib/license_normalizer.dart`). La table `_rpmToSpdx` et toute la logique `AND/OR/WITH` ont été retirées de ce fichier.

---

## `lib/spdx_generator.dart` — Générateur SPDX 2.3

Signature : `List<Package>`. Normalisation via `LicenseNormalizer.toSpdxExpression()`. Annotation type-aware :

```dart
String _annotationComment(Package pkg) {
  if (pkg is RpmPackage)
    return 'arch=${pkg.arch}; epoch=${pkg.epoch}; release=${pkg.release}…';
  if (pkg is WheelPackage)
    return '${pkg.packageType == "pypi" ? "pypi" : "source"}:platform=${pkg.arch}';
  if (pkg is DebPackage)
    return 'deb:arch=${pkg.arch}';
}
```

---

## `lib/spdx3_generator.dart` — Générateur SPDX 3.0 JSON-LD

Signature : `List<Package>`. Normalisation via `LicenseNormalizer.toSpdxExpression()`. Même logique d'annotation que SPDX 2.3 (branche `DebPackage` incluse). `_buildVendorElements` crée un nœud `Organization` par valeur unique de `pkg.vendor` (fonctionne pour tous les types).

---

## `lib/simple_json_generator.dart` — Générateur JSON personnalisé

Signature : `List<Package>`. Le champ `packageType` est inclus dans chaque entrée. Les champs RPM-spécifiques (`release`, `epoch`, `buildTime`) sont ajoutés conditionnellement :

```dart
if (pkg is RpmPackage) {
  base['release'] = pkg.release;
  base['epoch']   = pkg.epoch;
  base['buildTime'] = pkg.buildTime;
}
```

---

## `lib/markdown_generator.dart` — Tableau Markdown

Signature : `List<Package>`. Génère un tableau trié alphabétiquement par nom. La résolution des dépendances est skippée en amont (format `markdown` dans le `switch`). Affiche `(inconnue)` si `pkg.license` est vide.

---

## Flux de données — exemples concrets

### RPM : `bash` depuis un fichier .rpm

```
1. Détection : .rpm → RpmParser.parsePackage()
2. rpm -qp --queryformat '…' → "bash|5.1.8|6.el9|x86_64|(none)|GPL-3.0-or-later|…"
3. RpmPackage : bomRef="pkg-bash-5.1.8-6.el9-x86_64", purl="pkg:rpm/bash@5.1.8-6.el9?arch=x86_64"
4. LicenseNormalizer.toCycloneDxLicenses("GPL-3.0-or-later")
   → normalised = "GPL-3.0-or-later" (pas d'opérateur booléen)
   → mapped = "GPL-3.0-or-later" (pas dans _rpmToSpdx, mais isVersioned=true)
   → {"license": {"id": "GPL-3.0-or-later"}}
```

### Python wheel : `requests-2.28.2-py3-none-any.whl`

```
1. Détection : .whl → WheelParser.parseWheelFile()
2. python3 zipfile → requests-2.28.2.dist-info/METADATA
3. _parseRfc822() → {name: "requests", version: "2.28.2", license: "Apache-2.0", …}
4. _platformFromFilename() → "any" (dernier segment avant .whl)
5. WheelPackage : packageType='pypi', bomRef="pkg-pypi-requests-2.28.2"
                  purl="pkg:pypi/requests@2.28.2"
```

### Archive générique : `mariadb-11.4.8-linux-systemd-x86_64.tar.gz`

```
1. Détection : .tar.gz → TarParser.parseTarFile()
2. python3 tarfile : pas de PKG-INFO → type='generic'
   fichier COPYING trouvé → 2 KB extraits
3. _parseFilename() :
   segments=[mariadb, 11.4.8, linux, systemd, x86_64]
   versionIdx=1 ("11.4.8" ≅ ^\d+\.\d+)
   filtrage plateforme : linux, systemd, x86_64 retirés
   → name="mariadb", version="11.4.8", arch="x86_64"
4. _identifyLicense(COPYING) :
   title[:300] contient "GNU GENERAL PUBLIC LICENSE" + "Version 2"
   → "GPL-2.0-only"
5. WheelPackage : packageType='source', purl="pkg:generic/mariadb@11.4.8"
```

### Python sdist : `Django-4.2.1.tar.gz`

```
1. Détection : .tar.gz → TarParser.parseTarFile()
2. python3 tarfile : PKG-INFO trouvé → type='python', contenu RFC 822
3. Délégation à WheelParser.parseMetadataText(path, content)
4. WheelPackage : packageType='pypi', purl="pkg:pypi/django@4.2.1"
```

### Paquet Debian : `libssl3_3.0.1-1_amd64.deb`

```
1. Détection : .deb → DebParser.parseDebFile()
2. dpkg-deb -f → control RFC 822 : "Package: libssl3\nVersion: 3.0.1-1\n..."
3. _parseControl() → {Package: libssl3, Version: 3.0.1-1, Architecture: amd64, …}
4. _parseDependsList("libc6 (>= 2.17), libgcc-s1") → ["libc6", "libgcc-s1"]
5. DebPackage : bomRef="pkg-deb-libssl3-3.0.1-1-amd64",
               purl="pkg:deb/libssl3@3.0.1-1?arch=amd64"
```

### Requirements.txt : `/opt/reqs/requirements.txt`

```
1. Détection : .txt → pré-expansion RequirementsParser (avant la boucle concurrente)
2. Lecture ligne par ligne : "requests==2.28.0\nnumpy>=1.24\nflask\n"
3. _parseLine("requests==2.28.0") → WheelPackage(name="requests", version="2.28.0",
                                                  packageType="pypi")
4. _parseLine("flask") → WheelPackage(name="flask", version="", packageType="pypi")
5. Résultats ajoutés à preloadedPackages (puis packages après boucle principale)
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

2. Dans `bin/sbom_generator.dart` :

```dart
import 'package:sbom_generator/mon_format_generator.dart';

// ArgParser :
allowed: ['cyclonedx', 'spdx', 'spdx3', 'json', 'markdown', 'mon-format'],

// switch :
case 'mon-format':
  await MonFormatGenerator().writeToFile(
    uniquePackages, dependencies, outputPath, documentName: docName);
```

### Ajouter un nouveau type de paquet

1. Dans `lib/models.dart` : créer `class MonPackage extends Package { … }`
2. Créer `lib/mon_parser.dart` avec une méthode `Future<MonPackage?> parse(String path)`
3. Dans `bin/sbom_generator.dart` : ajouter la détection d'extension et le dispatch
4. Dans chaque générateur : ajouter `else if (pkg is MonPackage) { … }` pour les propriétés spécifiques

---

## Pièges et décisions de conception

### 1. Séparateur `|` dans SUMMARY (RPM)

`SUMMARY` peut contenir des `|`. Il est placé en dernier dans `_queryFormat` et les fragments ≥ index 11 sont rejoints.

### 2. Doublons de bomRef (RPM)

Même NEVRA dans plusieurs dépôts → même `bomRef` → interdit par CycloneDX. La déduplication dans `main()` supprime le deuxième exemplaire.

### 3. `LicenseRef-*` dans CycloneDX

`license.id` est validé contre la liste SPDX officielle. `LicenseRef-*` n'en fait pas partie (dans le schéma embarqué de sbomqs v2.0.6). Utiliser `{"license": {"name": "…"}}` à la place.

### 4. Champ `acknowledgement` (CycloneDX 1.6.1)

Ajouté après la version du schéma embarqué dans sbomqs. Son utilisation cause une erreur de validation. Ne pas l'utiliser.

### 5. `_capabilityName` et les modules Python RPM

`split(RegExp(r'[\s(]'))` tronquerait `python3dist(lxml)` en `python3dist`, créant de faux positifs. Le split sur `\s+[<>=!]` préserve les parenthèses.

### 6. Faux positif GPL → LGPL dans la détection de licence

Le texte GPL-2.0 mentionne « GNU Library General Public License » dans sa section « How to Apply ». La détection LGPL ne porte que sur les 300 premiers caractères (titre du document), pas sur le corps complet.

### 7. Dépendances Python intra-liste

La résolution fonctionne si les noms sont normalisés de manière cohérente (PEP 503). `WheelPackage.provides` contient le nom normalisé ; `Requires-Dist` est aussi normalisé au parsing. `buildDependencies` ajoute de plus `pkg.name` brut à `providesMap`, couvrant les deux formes.

### 8. Requirements.txt : cardinalité 1:N

Un fichier `.txt` unique peut produire N paquets. La boucle concurrente modélise `Future<Package?>` (1 ref → 0 ou 1 résultat), ce qui est incompatible avec la cardinalité 1:N. Solution : pré-expansion des `.txt` avant la boucle dans `preloadedPackages`.

### 9. Champ `License` absent dans de nombreux `.deb`

Le standard Debian ne rend pas le champ `License` obligatoire dans `DEBIAN/control`. `DebPackage.license` sera souvent vide, ce qui donne `NOASSERTION` dans SPDX et une liste `licenses` vide dans CycloneDX — comportement conforme, non une erreur.

### 10. Ordre préservé par `Future.wait(List.generate(...))`

`Future.wait` garantit que le résultat à l'index `i` correspond à l'entrée `i`. L'ordre d'apparition dans le SBOM final est donc identique à l'ordre du fichier d'entrée, malgré le traitement concurrent.

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

Les générateurs JSON exposent les deux méthodes (sauf `MarkdownGenerator` qui n'a que `writeToFile`). `generate()` retourne un `Map<String, dynamic>` testable sans I/O.

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
| `pkg.sourceRef` (si `.rpm`/`.whl`) | `externalReferences[distribution]` | — | — |
| **RPM** `release`, `epoch`, `arch`, `buildTime` | `properties[rpm:*]` | `annotations` | `annotation` |
| **RPM** `requires` × N | `properties[rpm:requires]` × N | — | — |
| **Python/Source** `arch` (platform tag) | `properties[pypi:/source:platform]` | `annotations` | `annotation` |
| **Python** `requires` × N | `properties[pypi:requires]` × N | — | — |
| **RPM** CPE calculé | `cpe` | — | — |
| **RPM** `sourceRpm` | `externalReferences[vcs]` | — | — |
| **Debian** `arch` | `properties[deb:arch]` | `annotations` | `annotation` |
| **Debian** `requires` × N | `properties[deb:depends]` × N | — | — |
| résolution requires/provides | `dependencies[].dependsOn` | `relationships[DEPENDS_ON]` | `Relationship[dependsOn]` |

---

## Performance et limites

### Coût de traitement par paquet

| Type | Appels subprocess | Temps estimé |
|------|------------------|-------------|
| RPM (installé ou fichier) | 3 × `rpm` en parallèle | ~15–50 ms |
| Wheel `.whl` | 1 × `python3` | ~20–50 ms |
| Archive tar (Python sdist) | 1 × `python3` | ~20–80 ms |
| Archive tar (générique) | 1 × `python3` | ~20–80 ms |
| Archive ZIP (générique ou sdist) | 1 × `python3` | ~20–80 ms |
| Paquet Debian `.deb` | 1 × `dpkg-deb` | ~5–20 ms |
| Requirements.txt | 0 subprocess | < 1 ms |

La boucle est parallélisée via `Future.wait()` + `_Semaphore(--concurrency)`. Avec `--concurrency 4` (défaut) sur une grande liste, le gain est ~4× par rapport à l'ancienne boucle séquentielle. Avec `--concurrency 0` (illimité), toutes les entrées sont lancées simultanément.

### Taille des fichiers générés

| Format | ~100 paquets | ~800 paquets |
|--------|-------------|-------------|
| CycloneDX | ~400 KB | ~3 MB |
| SPDX 2.3 | ~300 KB | ~2 MB |
| SPDX 3.0 JSON-LD | ~200 KB | ~1.5 MB |
| JSON personnalisé | ~800 KB | ~6 MB |
| Markdown | ~10 KB | ~80 KB |

### Limites connues

- **Pas de résolution transitive** : seules les dépendances entre paquets présents dans la liste sont incluses.
- **CPE approximatifs** : valides syntaxiquement, peuvent différer des entrées NVD officielles.
- **Licences archive heuristiques** : la détection depuis les fichiers LICENSE/COPYING est basée sur des patterns textuels, non sur une analyse exhaustive.
- **Champ License absent dans les `.deb`** : la plupart des paquets Debian n'incluent pas de champ `License` dans leur `control` — `DebPackage.license` sera vide, ce qui produit `NOASSERTION` dans SPDX.
- **Pas de vérification d'existence des fichiers** : si un chemin `.whl`, `.tar.gz`, `.zip` ou `.deb` n'existe pas, le subprocess échoue et le paquet est compté comme `échec`.

---

## Flux d'appel (call graph simplifié)

```
main()
  ├── ArgParser.parse()                       (--concurrency validé ≥ 0)
  ├── File.readAsLines()
  ├── [pré-expansion .txt]
  │     └── RequirementsParser.parseFile() → preloadedPackages
  ├── [indexation --rpm-dir]                  [si --rpm-dir spécifié]
  │     └── dir.list(recursive: true) → rpmExactIndex + rpmNameIndex
  ├── Process.run('rpm', ['--version'])       [si RPM présents]
  ├── Process.run('python3', ['--version'])   [si .whl, tar ou .zip présents]
  ├── Process.run('dpkg-deb', ['--version'])  [si .deb présents]
  ├── Future.wait(List.generate(N)) via _Semaphore(--concurrency)
  │     ├── RpmParser.parsePackage()          [si RPM]
  │     │     └── Future.wait([rpm-queryformat, rpm-requires, rpm-provides])
  │     ├── WheelParser.parseWheelFile()      [si .whl]
  │     │     └── Process.run('python3', ['-c', zipScript, path])
  │     ├── TarParser.parseTarFile()          [si tar]
  │     │     ├── Process.run('python3', ['-c', tarScript, path])
  │     │     └── WheelParser.parseMetadataText()  [si Python sdist]
  │     ├── ZipParser.parseZipFile()          [si .zip]
  │     │     ├── Process.run('python3', ['-c', zipScript, path])
  │     │     └── WheelParser.parseMetadataText()  [si Python sdist]
  │     └── DebParser.parseDebFile()          [si .deb]
  │           └── Process.run('dpkg-deb', ['-f', path])
  ├── packages.addAll(preloadedPackages)
  ├── [déduplication par bomRef]
  ├── RpmParser.buildDependencies(List<Package>)
  └── <Generator>.writeToFile(List<Package>, …)
        ├── _packageToComponent/_packageToSpdx/… × N
        │     ├── LicenseNormalizer.toCycloneDxLicenses() / toSpdxExpression()
        │     ├── if (pkg is RpmPackage) { … RPM-specific … }
        │     ├── else if (pkg is WheelPackage) { … Python/source … }
        │     └── else if (pkg is DebPackage) { … deb-specific … }
        └── File.writeAsString()
```

---

## Tests

```bash
dart test                            # tous les tests (67 au total)
dart test test/unit/                 # tests unitaires seuls (59)
dart test test/integration/          # tests d'intégration (8, requiert python3)
```

### Suites unitaires

| Fichier | Tests | Couverture |
|---------|-------|-----------|
| `test/unit/license_normalizer_test.dart` | 23 | `toSpdxExpression`, `toCycloneDxLicenses`, cas limites |
| `test/unit/archive_helpers_test.dart` | 18 | `parseArchiveFilename` (5 archives réelles + edge cases), `identifyArchiveLicense` (10 licences) |
| `test/unit/rpm_parser_test.dart` | 8 | `buildDependencies` sans subprocess |
| `test/unit/requirements_parser_test.dart` | 10 | parsing RFC, PEP 503, extras, marqueurs, directives |

### Suite d'intégration

| Fichier | Tests | Couverture |
|---------|-------|-----------|
| `test/integration/tar_integration_test.dart` | 8 | TarParser sur 5 archives réelles, WheelParser sur 2 wheels, bomRefs uniques |

Les tests d'intégration sont marqués `@TestOn('posix')` et se sautent automatiquement si `python3` est absent.

---

## Checklist avant modification

- [ ] `dart analyze` passe sans erreur ni avertissement (`No issues found!`)
- [ ] `dart format --output=none lib/ bin/` passe sans différence
- [ ] `dart test` — tous les 67 tests verts
- [ ] Test sur les 5 archives 3PP (nom, version, arch, licence corrects)
- [ ] Test avec liste mixte RPM + .whl + .tar.gz + .zip + .deb + requirements.txt
- [ ] Si modification de `--rpm-dir` : vérifier résolution exacte (NEVRA), résolution par nom, avertissement multi-match, fallback `rpm -q` si absent
- [ ] Le SBOM CycloneDX passe `sbom_schema_valid: 10.0` dans sbomqs
- [ ] Pas de `bom-ref` dupliqués dans la sortie CycloneDX
- [ ] Si modification de `LicenseNormalizer` : relancer `test/unit/license_normalizer_test.dart` (23 cas)
- [ ] Si modification de `identifyArchiveLicense` : vérifier que GPL-2.0 (MariaDB COPYING) n'est pas détecté comme LGPL
- [ ] Si modification de `parseArchiveFilename` : vérifier les 5 cas 3PP du tableau dans `archive_helpers_test.dart`
- [ ] Si modification de `_capabilityName` : vérifier `python3dist(lxml) >= 3.0` → `python3dist(lxml)`
- [ ] Si ajout d'un type de paquet : mettre à jour `models.dart`, tous les générateurs (`if (pkg is …)`), `bin/sbom_generator.dart` (dispatch + outil check) et ce document

---

## Dépendances externes

| Package | Version | Rôle |
|---------|---------|------|
| `args` | `^2.4.2` | Parsing des arguments CLI |
| `test` *(dev)* | `^1.24.0` | Framework de tests unitaires et d'intégration |

Tout le reste : bibliothèque standard Dart (`dart:io`, `dart:convert`, `dart:math`, `dart:async`).

Outils système requis à l'exécution :

| Outil | Requis pour |
|-------|------------|
| `rpm` | paquets RPM (installés ou fichiers `.rpm`) |
| `python3` + `zipfile` + `tarfile` (stdlib) | wheels `.whl`, archives `.tar*` et `.zip` |
| `dpkg-deb` | paquets Debian `.deb` |

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
