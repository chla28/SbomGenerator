# sbom_generator — Documentation développeur

Ce document explique le fonctionnement interne du code pour une prise en main rapide.

---

## Architecture générale

Le programme suit un pipeline linéaire :

```
Fichier d'entrée (.txt)
        │
        ▼
┌───────────────────────────────────────┐
│  bin/sbom_generator.dart              │  1. Lecture + validation CLI
│  (main + _printProgress)              │  2. Détection du type par extension
│                                       │  3. Dispatch vers le bon parser
│                                       │  4. Déduplication par bomRef
└──┬──────────┬──────────┬──────────────┘
   │          │          │
   ▼          ▼          ▼
RpmParser  WheelParser  TarParser
   │          │          │
   └──────────┴──────────┘
              │  List<Package>
              ▼
   RpmParser.buildDependencies()
              │  List<PackageDependency>
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

Tous les générateurs travaillent sur `List<Package>` — la classe abstraite commune à `RpmPackage` et `WheelPackage`.

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
  String get packageType;   // 'rpm' | 'pypi' | 'source'
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

Trois appels `rpm` séquentiels :
1. `rpm -q[p] --queryformat ...` → 12 champs de métadonnées
2. `rpm -q[p] --requires` → liste des capabilities requises
3. `rpm -q[p] --provides` → liste des capabilities fournies

Retourne `null` avec un avertissement sur `stderr` en cas d'échec.

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

Si `type == 'generic'` : `_buildGenericPackage()` :
1. Analyse le nom de fichier via `_parseFilename()`
2. Identifie la licence via `_identifyLicense()`
3. Retourne un `WheelPackage` avec `packageType='source'`

### Parsing du nom de fichier (`_parseFilename`)

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

### Identification de licence (`_identifyLicense`)

Travaille sur les 2 000 premiers caractères du fichier de licence. Utilise deux zones :

- **`title`** (300 premiers chars) pour les familles GPL/LGPL — évite le faux positif : GPL-2.0 mentionne « GNU Library General Public License » dans son corps, mais pas dans son titre.
- **`lower`** (2 000 chars) pour Apache, MIT, SSPL, MPL, etc.

Licences reconnues : `SSPL-1.0`, `Apache-2.0`, `Apache-1.1`, `GPL-2.0-only`, `GPL-3.0-only`, `LGPL-2.0-only`, `LGPL-2.1-only`, `LGPL-3.0-only`, `MPL-2.0`, `MPL-1.1`, `MIT`, `ISC`, `BSD-2-Clause`, `BSD-3-Clause`, `EPL-2.0`, `EPL-1.0`, `CDDL-1.0`.

> **Piège :** Le texte GPL-2.0 contient « use the GNU Library General Public License instead » dans la section « How to Apply ». Vérifier uniquement le titre (300 premiers chars) empêche ce faux positif LGPL.

---

## `bin/sbom_generator.dart` — Point d'entrée

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

Les références `.whl` et archives tar ne sont jamais concernées, même si `--rpm-dir` est spécifié.

### Dispatch par extension

```dart
if (ref.endsWith('.whl')) {
  pkg = await whlParser.parseWheelFile(ref);
} else if (_isTar(ref)) {          // .tar | .tar.gz | .tgz
  pkg = await tarParser.parseTarFile(ref);
} else {
  pkg = await rpmParser.parsePackage(ref);
}
```

### Vérification des outils

`rpm` est vérifié seulement si la liste contient au moins une référence non-`.whl` non-tar. `python3` est vérifié si la liste contient au moins un `.whl` ou une archive tar.

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

## `lib/cyclonedx_generator.dart` — Générateur CycloneDX 1.6

### Signature mise à jour

```dart
Map<String, dynamic> generate(List<Package> packages, List<PackageDependency> dependencies, ...)
```

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

### Normalisation des licences (`_buildLicenses`)

Algorithme à 4 étapes (inchangé) :
1. Normalisation des opérateurs booléens (`and` → `AND`, `or` → `OR`, `with` → `WITH`) avec lookbehind/lookahead `\S` pour protéger `GPL-2.0-or-later`.
2. Détection expression composée (`AND`/`OR`/`WITH`) → `{"expression": "…"}`.
3. Résolution dans `_rpmToSpdx` (~70 entrées).
4. Choix du champ : `id` (SPDX connu), `name` (LicenseRef-* ou inconnu), `expression` (composé).

---

## `lib/spdx_generator.dart` — Générateur SPDX 2.3

Signature : `List<Package>`. Annotation type-aware :

```dart
String _annotationComment(Package pkg) {
  if (pkg is RpmPackage)
    return 'arch=${pkg.arch}; epoch=${pkg.epoch}; release=${pkg.release}…';
  if (pkg is WheelPackage)
    return '${pkg.packageType == "pypi" ? "pypi" : "source"}:platform=${pkg.arch}';
}
```

---

## `lib/spdx3_generator.dart` — Générateur SPDX 3.0 JSON-LD

Signature : `List<Package>`. Même logique d'annotation que SPDX 2.3. `_buildVendorElements` crée un nœud `Organization` par valeur unique de `pkg.vendor` (fonctionne pour tous les types).

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
4. _buildLicenses("GPL-3.0-or-later")
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
| résolution requires/provides | `dependencies[].dependsOn` | `relationships[DEPENDS_ON]` | `Relationship[dependsOn]` |

---

## Performance et limites

### Coût de traitement par paquet

| Type | Appels subprocess | Temps estimé |
|------|------------------|-------------|
| RPM (installé ou fichier) | 3 × `rpm` | ~15–50 ms |
| Wheel `.whl` | 1 × `python3` | ~20–50 ms |
| Archive tar (Python sdist) | 1 × `python3` | ~20–80 ms |
| Archive tar (générique) | 1 × `python3` | ~20–80 ms |

La boucle est séquentielle. Une parallélisation avec `Future.wait()` réduirait le temps d'un facteur ~4–8 mais mélangerait les messages d'erreur.

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
- **Licences tar heuristiques** : la détection depuis les fichiers LICENSE est basée sur des patterns textuels, non sur une analyse exhaustive.
- **Pas de vérification d'existence des fichiers** : si un chemin `.whl` ou `.tar.gz` n'existe pas, python3 échoue et le paquet est compté comme `échec`.

---

## Flux d'appel (call graph simplifié)

```
main()
  ├── ArgParser.parse()
  ├── File.readAsLines()
  ├── [indexation --rpm-dir]                  [si --rpm-dir spécifié]
  │     └── dir.list(recursive: true) → rpmExactIndex + rpmNameIndex
  ├── Process.run('rpm', ['--version'])       [si RPM présents]
  ├── Process.run('python3', ['--version'])   [si .whl ou tar présents]
  ├── _printProgress()
  ├── [résolution --rpm-dir par référence]    [si --rpm-dir spécifié]
  ├── RpmParser.parsePackage() × N_rpm
  │     ├── Process.run('rpm', ['--queryformat', …])
  │     ├── Process.run('rpm', ['--requires', …])
  │     └── Process.run('rpm', ['--provides', …])
  ├── WheelParser.parseWheelFile() × N_whl
  │     └── Process.run('python3', ['-c', zipScript, path])
  ├── TarParser.parseTarFile() × N_tar
  │     ├── Process.run('python3', ['-c', tarScript, path])
  │     └── WheelParser.parseMetadataText()  [si Python sdist]
  ├── [déduplication par bomRef]
  ├── RpmParser.buildDependencies(List<Package>)
  └── <Generator>.writeToFile(List<Package>, …)
        ├── _packageToComponent/_packageToSpdx/… × N
        │     ├── _buildLicenses() / _identifyLicense()
        │     └── if (pkg is RpmPackage) { … RPM-specific … }
        │         else if (pkg is WheelPackage) { … Python/source … }
        └── File.writeAsString()
```

---

## Checklist avant modification

- [ ] `dart analyze` passe sans erreur ni avertissement (`No issues found!`)
- [ ] `dart format --output=none lib/ bin/` passe sans différence
- [ ] Test sur les 5 archives 3PP (nom, version, arch, licence corrects)
- [ ] Test avec liste mixte RPM + .whl + .tar.gz
- [ ] Si modification de `--rpm-dir` : vérifier résolution exacte (NEVRA), résolution par nom, avertissement multi-match, fallback `rpm -q` si absent
- [ ] Le SBOM CycloneDX passe `sbom_schema_valid: 10.0` dans sbomqs
- [ ] Pas de `bom-ref` dupliqués dans la sortie CycloneDX
- [ ] Si modification de `_buildLicenses` : tester licences composées (`GPL-2.0-or-later AND MIT`) et cas limites (`(none)`, `LicenseRef-PublicDomain`)
- [ ] Si modification de `_identifyLicense` : vérifier que GPL-2.0 (MariaDB COPYING) n'est pas détecté comme LGPL
- [ ] Si modification de `_parseFilename` : vérifier les 5 cas 3PP du tableau ci-dessus
- [ ] Si modification de `_capabilityName` : vérifier `python3dist(lxml) >= 3.0` → `python3dist(lxml)`
- [ ] Si ajout d'un type de paquet : mettre à jour tous les générateurs (`if (pkg is …)`) et ce document

---

## Dépendances externes

| Package | Version | Rôle |
|---------|---------|------|
| `args` | `^2.4.2` | Parsing des arguments CLI |

Tout le reste : bibliothèque standard Dart (`dart:io`, `dart:convert`, `dart:math`).

Outils système requis à l'exécution :

| Outil | Requis pour |
|-------|------------|
| `rpm` | paquets RPM (installés ou fichiers `.rpm`) |
| `python3` + `zipfile` (stdlib) | wheels `.whl` et archives `.tar*` |

---

## Compilation et déploiement

```bash
# Développement (JIT, compile à la volée)
dart run bin/sbom_generator.dart -i packages.txt

# Binaire natif autonome (AOT, ~30 s de compilation)
dart compile exe bin/sbom_generator.dart -o sbom_generator

# Analyse statique
dart analyze

# Formatage
dart format lib/ bin/
dart format --output=none lib/ bin/   # mode CI (pas de modification)
```
