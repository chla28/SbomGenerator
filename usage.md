# sbom_generator — Guide d'utilisation

Générateur de SBOM (Software Bill of Materials) à partir d'une liste de paquets RPM.
Prend en charge les formats **CycloneDX 1.6/1.7**, **SPDX 2.3**, **SPDX 3.0 JSON-LD** et un format **JSON personnalisé**.

---

## Prérequis

| Composant | Version minimale | Rôle |
|-----------|-----------------|------|
| [Dart SDK](https://dart.dev/get-dart) | 3.0.0 | Compilation et exécution |
| `rpm` | — | Interrogation des métadonnées RPM |

Vérification :
```bash
dart --version
rpm --version
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
```

### Options

| Option | Raccourci | Défaut | Description |
|--------|-----------|--------|-------------|
| `--input <fichier>` | `-i` | *(requis)* | Fichier contenant la liste des RPM |
| `--output <fichier>` | `-o` | `sbom.json` | Fichier SBOM de sortie |
| `--format <fmt>` | `-f` | `cyclonedx` | Format de sortie (voir ci-dessous) |
| `--name <nom>` | `-n` | `RPM Package Set` | Nom du document SBOM / composant racine |
| `--cyclonedx-version <ver>` | | `1.6` | Version CycloneDX générée : `1.6` ou `1.7` |
| `--tlp <classification>` | | | Classification TLP du BOM (1.7 uniquement) : `CLEAR`, `GREEN`, `AMBER`, `AMBER_AND_STRICT`, `RED` |
| `--patent-map <fichier>` | | | Déclarations de brevets par paquet (1.7 uniquement, voir ci-dessous) |
| `--verbose` | `-v` | désactivé | Affiche les détails de progression |
| `--version` | | | Affiche la version et quitte |
| `--help` | `-h` | | Affiche l'aide |

### Formats disponibles

| Valeur | Standard | Version | Description |
|--------|----------|---------|-------------|
| `cyclonedx` | CycloneDX | 1.6 ou 1.7 | Format par défaut (1.6). JSON conforme au schéma CycloneDX ; `--cyclonedx-version 1.7` active en plus `citations`, `patentAssertions` et `distributionConstraints`. |
| `spdx` | SPDX | 2.3 | JSON SPDX 2.3 avec `packages[]` et `relationships[]`. |
| `spdx3` | SPDX | 3.0 | JSON-LD SPDX 3.0 avec graphe plat d'éléments (`@graph`). |
| `json` | Personnalisé | 1.0 | JSON lisible incluant toutes les métadonnées RPM brutes. |

#### Déclarations de brevets (`--patent-map`, CycloneDX 1.7)

Fichier texte, une déclaration par ligne :
```
package_name: numéro_brevet|juridiction|statut_légal|type_assertion
openssl: US1234567|US|granted|license
```
- `juridiction` : code WIPO ST.3 à 2 lettres (`US`, `EP`, `JP`…)
- `statut_légal` : `pending`, `granted`, `revoked`, `expired`, `lapsed`, `withdrawn`, `abandoned`, `suspended`, `reinstated`, `opposed`, `terminated`, `invalidated`, `in-force`
- `type_assertion` : `ownership`, `license`, `third-party-claim`, `standards-inclusion`, `prior-art`, `exclusive-rights`, `non-assertion`, `research-or-evaluation`

Quand `--image` est utilisé avec `--cyclonedx-version 1.7`, une `citation` racine attribue automatiquement les données de composants à l'outil d'analyse choisi (`--oci-tool`).

---

## Format du fichier d'entrée

Un fichier texte, **une référence RPM par ligne**.

### Types de références acceptées

| Type | Exemple | Mécanisme |
|------|---------|-----------|
| Nom de paquet installé | `bash` | `rpm -q bash` |
| NEVRA complet | `bash-5.1.8-6.el9.x86_64` | `rpm -q bash-5.1.8-6.el9.x86_64` |
| Chemin vers un fichier `.rpm` | `/mnt/repo/bash-5.1.8.rpm` | `rpm -qp /mnt/repo/bash-5.1.8.rpm` |

### Règles de syntaxe

- Les lignes vides sont ignorées.
- Les lignes commençant par `#` sont des commentaires et sont ignorées.
- Les paquets identiques (même NEVRA, présents dans plusieurs dépôts) sont automatiquement dédupliqués.

### Exemple de fichier d'entrée

```text
# Système de base RHEL 9
bash
glibc
openssl-libs
systemd

# Paquets réseau
NetworkManager
NetworkManager-team

# Fichiers RPM locaux
/mnt/BaseOS/Packages/curl-7.76.1-14.el9.x86_64.rpm
/mnt/AppStream/Packages/nginx-1.20.1-14.el9.x86_64.rpm

# Commenter un paquet temporairement
# python3
```

### Générer la liste depuis un système installé

```bash
# Tous les paquets installés
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

### Fichiers RPM depuis un dépôt monté

```bash
find /mnt/BaseOS/Packages -name '*.rpm' > liste.txt
find /mnt/AppStream/Packages -name '*.rpm' >> liste.txt
./sbom_generator -i liste.txt -f cyclonedx -n "RHEL 9 BaseOS+AppStream" -o rhel9.cdx.json
```

### Pipeline complet : génération + validation qualité

```bash
# Génération
./sbom_generator -i rpm97.lst -f cyclonedx -n "RHEL9 Base System" -o sbom.cdx.json

# Validation de qualité avec sbomqs
./sbomqs score sbom.cdx.json
```

---

## Ce que contient le SBOM généré

### Métadonnées du document

| Champ | Contenu |
|-------|---------|
| Timestamp | Date/heure de génération (UTC ISO 8601) |
| Outil | `sbom_generator 1.0.0` |
| Auteur | Configurable via `--name` |
| Supplier | Organisation productrice du SBOM |
| Lifecycle | `operations` (par défaut) |
| Data license | `CC0-1.0` |

### Par composant (paquet RPM)

| Champ | Source RPM | Description |
|-------|-----------|-------------|
| Nom | `%{NAME}` | Nom du paquet |
| Version | `%{VERSION}-{%RELEASE}` | Version complète avec release |
| PURL | calculé | `pkg:rpm/<name>@<version>?arch=<arch>` |
| CPE 2.3 | calculé | `cpe:2.3:a:<vendor>:<name>:<version>:*:…` |
| Checksum | `%{SHA256HEADER}` | SHA-256 de l'en-tête RPM |
| Licence | `%{LICENSE}` | Normalisée vers SPDX (expression ou id) |
| Supplier | `%{VENDOR}` | Fournisseur du paquet |
| Description | `%{SUMMARY}` | Résumé court |
| VCS | `%{SOURCERPM}` | Lien vers le RPM source (Fedora/RHEL) |
| Propriétés | `rpm:arch`, `rpm:release`, `rpm:requires` | Métadonnées RPM additionnelles |

### Dépendances

Les dépendances sont résolues **au sein de la liste fournie** :
- `rpm -q --requires <pkg>` → liste des capabilities requises
- `rpm -q --provides <pkg>` → liste des capabilities fournies
- Résolution : si le paquet A requiert une capability que le paquet B fournit, une relation `A → B` est ajoutée
- Les dépendances externes (glibc, systemd…) non présentes dans la liste apparaissent dans les propriétés `rpm:requires` mais pas dans `dependsOn`

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

Chaque `dependencies[].dependsOn` contient les `bom-ref` des paquets dont dépend le composant. L'entrée racine liste tous les composants du SBOM.

Avec `--cyclonedx-version 1.7`, des champs supplémentaires apparaissent selon les options fournies :
- `metadata.distributionConstraints.tlp` (`--tlp`)
- `citations[]` racine attribuant `/components` à l'outil source (automatique avec `--image`)
- `components[].patentAssertions[]` + `definitions.patents[]` (`--patent-map`)

Ces champs n'existent pas dans le schéma CycloneDX 1.6 : ils sont donc uniquement émis quand `--cyclonedx-version 1.7` est actif (une erreur est levée sinon).

### SPDX 2.3 (`spdx`)

Structure JSON :
```
{
  "spdxVersion": "SPDX-2.3",
  "creationInfo": { created, creators },
  "packages": [ { SPDXID, name, versionInfo, downloadLocation, licenseConcluded,
                   licenseDeclared, copyrightText, externalRefs, annotations } ],
  "relationships": [ { spdxElementId, relationshipType, relatedSpdxElement } ]
}
```

Types de relations : `DESCRIBES` (document → paquets) et `DEPENDS_ON` (dépendances résolues).

### SPDX 3.0 JSON-LD (`spdx3`)

Structure JSON-LD :
```
{
  "@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
  "@graph": [
    { type: "SpdxDocument", profileConformance: ["core","software"], … },
    { type: "CreationInfo", specVersion: "3.0.0", … },
    { type: "Tool", … },
    { type: "Organization", … },         ← un par fournisseur unique
    { type: "software:Package", … },     ← un par paquet RPM
    { type: "Relationship", relationshipType: "describes", … },
    { type: "Relationship", relationshipType: "dependsOn", … }
  ]
}
```

### JSON personnalisé (`json`)

Inclut toutes les métadonnées RPM brutes (`requires`, `provides`) ainsi que les dépendances résolues en noms lisibles. Idéal pour du scripting ou de l'intégration personnalisée.

---

## Scores de qualité sbomqs

Résultats obtenus sur 772 paquets RHEL 9 (`rpm97.lst`) avec le format CycloneDX :

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

- `comp_with_licenses` et `comp_with_valid_licenses` **ne sont pas implémentés** pour CycloneDX dans cette version de sbomqs (toujours 0, indépendamment du contenu)
- `comp_with_dependencies` : le mécanisme `compositions` n'est pas reconnu
- `sbom_signature` : nécessite une clé cryptographique externe

---

## Architecture du projet

```
sbom_generator/
├── bin/
│   └── sbom_generator.dart        # Point d'entrée CLI
├── lib/
│   ├── models.dart                # RpmPackage, PackageDependency, UUID
│   ├── rpm_parser.dart            # Interrogation rpm + résolution dépendances
│   ├── cyclonedx_generator.dart   # Générateur CycloneDX 1.6/1.7
│   ├── spdx_generator.dart        # Générateur SPDX 2.3
│   ├── spdx3_generator.dart       # Générateur SPDX 3.0 JSON-LD
│   └── simple_json_generator.dart # Générateur JSON personnalisé
├── sbom_generator                 # Binaire natif compilé
├── pubspec.yaml                   # Dépendances Dart (args ^2.4.2)
├── rpm97.lst                      # Exemple : liste RHEL 9
├── rpm97.cdx.json                 # Exemple : SBOM CycloneDX généré
└── sbomqs                         # Outil de mesure de qualité
```

---

## Dépannage

### `rpm: command not found`

Installez le paquet `rpm` :
```bash
# Fedora/RHEL
sudo dnf install rpm

# Debian/Ubuntu
sudo apt install rpm
```

### `Warning: cannot query "pkg"`

Le paquet n'est pas installé ou le fichier `.rpm` est inaccessible.
Vérifiez avec `rpm -q <paquet>` ou `rpm -qp <fichier.rpm>`.

### Doublons dans la liste d'entrée

Si le même paquet (même NEVRA) apparaît plusieurs fois (par ex. présent dans BaseOS et AppStream), il n'est inclus qu'une seule fois dans le SBOM. Un message `($N doublon(s) supprimé(s))` l'indique.

### Fichier SBOM très volumineux

Les propriétés `rpm:requires` peuvent représenter 50 à 150 entrées par paquet. Sur 779 paquets, le fichier CycloneDX peut atteindre 3 Mo. C'est normal.
