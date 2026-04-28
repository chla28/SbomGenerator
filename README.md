# sbom_generator

Génère un SBOM (Software Bill of Materials) à partir d'une liste mixte de paquets RPM, Python wheels et archives sources.

---

## Ce que fait le programme

**Entrée** — un fichier texte, une référence par ligne :

| Type | Exemples | Outil requis |
|------|----------|--------------|
| RPM installé | `bash`, `glibc-2.42`, `openssl-libs-3.0` | `rpm` |
| Fichier `.rpm` local | `/tmp/mypkg-1.0-1.el9.x86_64.rpm` | `rpm` |
| Python wheel `.whl` | `/opt/wheels/requests-2.28.0-py3-none-any.whl` | `python3` |
| Python sdist `.tar.gz` / `.tgz` | `/opt/src/Django-4.2.1.tar.gz` | `python3` |
| Archive source générique | `/opt/3PP/apache-tomcat-10.1.44.tar.gz` | `python3` |

Les lignes commençant par `#` sont ignorées. Les types peuvent être mélangés librement dans un même fichier.

**Traitement :**
- RPM : interrogation via `rpm -q --queryformat` + `--requires` / `--provides`
- Wheel : lecture du fichier `METADATA` embarqué dans le ZIP
- Archive tar : détection du type (Python sdist si `PKG-INFO` présent, sinon générique), lecture des fichiers `LICENSE` / `COPYING` pour la licence

**Formats de sortie :**

| `-f` | Standard | Contenu |
|------|----------|---------|
| `cyclonedx` | CycloneDX 1.6 JSON *(défaut)* | `components[]` + `dependencies[]` + `compositions[]` |
| `spdx` | SPDX 2.3 JSON | `packages[]` + `relationships[]` |
| `spdx3` | SPDX 3.0 JSON-LD | graphe `@graph` (éléments, relations, organisations) |
| `json` | JSON personnalisé | métadonnées complètes + graphe de dépendances résolu |
| `markdown` | Tableau Markdown | tableau `Paquet / Version / Architecture / Licence` |

---

## Installation

### Prérequis

- Dart SDK ≥ 3.0
- `rpm` (pour les paquets RPM)
- `python3` (pour les wheels et archives tar)

### Compiler l'exécutable natif

```bash
dart compile exe bin/sbom_generator.dart -o sbom_generator
```

---

## Usage

```
sbom_generator --input <fichier> [options]

Options :
  -i, --input      Fichier d'entrée (requis)
  -o, --output     Fichier de sortie (défaut : sbom.json)
  -f, --format     Format : cyclonedx | spdx | spdx3 | json | markdown
  -n, --name       Nom du document SBOM / composant racine
  -d, --rpm-dir    Dossier racine où chercher les fichiers .rpm
                   (résout les noms RPM nus ; ne s'applique pas aux .whl/.tar)
  -v, --verbose    Afficher les détails
      --version    Afficher la version
  -h, --help       Afficher l'aide
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

# Résoudre les noms RPM depuis un dossier local (pas de rpm installé requis)
./sbom_generator -i packages.txt -d /mnt/repo -o sbom.cdx.json
```

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

# Archives binaires tierces (Tomcat, MariaDB, MongoDB…)
/opt/3PP/apache-tomcat-10.1.44.tar.gz
/opt/3PP/mariadb-11.4.8-linux-systemd-x86_64.tar.gz
/opt/3PP/mongodb-linux-x86_64-rhel8-8.0.12.tgz
```

---

## Comportement selon le type d'archive tar

| Contenu de l'archive | Résultat |
|----------------------|----------|
| `PKG-INFO` ou `*.dist-info/METADATA` | Python sdist → PURL `pkg:pypi/…`, métadonnées complètes |
| `LICENSE` / `COPYING` / `LICENSE-*` (sans PKG-INFO) | Archive générique → PURL `pkg:generic/…`, licence identifiée depuis le fichier |
| Ni l'un ni l'autre | Archive générique → nom/version déduits du nom de fichier, licence inconnue |

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
│   └── sbom_generator.dart      # Point d'entrée CLI
├── lib/
│   ├── models.dart              # Package (abstrait), RpmPackage, WheelPackage,
│   │                            #   PackageDependency, generateUuidV4()
│   ├── rpm_parser.dart          # Interrogation du binaire rpm
│   ├── wheel_parser.dart        # Lecture des .whl (ZIP + RFC 822)
│   ├── tar_parser.dart          # Lecture des .tar/.tar.gz/.tgz
│   ├── cyclonedx_generator.dart # Format CycloneDX 1.6 JSON
│   ├── spdx_generator.dart      # Format SPDX 2.3 JSON
│   ├── spdx3_generator.dart     # Format SPDX 3.0 JSON-LD
│   ├── simple_json_generator.dart  # Format JSON personnalisé
│   └── markdown_generator.dart  # Tableau Markdown des licences
├── 3PP/                         # Exemples d'archives tierces
├── pubspec.yaml
└── README.md
```

---

## PURLs générés par type de paquet

| Type | PURL | Exemple |
|------|------|---------|
| RPM | `pkg:rpm/<name>@<ver>?arch=<arch>` | `pkg:rpm/bash@5.1.8-6.el9?arch=x86_64` |
| Python (wheel / sdist) | `pkg:pypi/<name>@<ver>` | `pkg:pypi/requests@2.28.2` |
| Archive générique | `pkg:generic/<name>@<ver>` | `pkg:generic/apache-tomcat@10.1.44` |
