# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Parseurs manifestes : Go (`go.sum`, `go.mod`), npm (`package-lock.json`), yarn (`yarn.lock`), Maven (`pom.xml`)
- Format de sortie CSV (RFC 4180) avec colonnes : nom, version, type, purl, licence, description, fournisseur
- Sous-commande `convert` : conversion entre formats CycloneDX 1.5, SPDX 2.3, SPDX 3.0 et CSV
- Sous-commande `validate` : validation structurelle des SBOM existants (option `--strict`)
- `SbomReader` : lecteur SBOM supportant CycloneDX 1.x, SPDX 2.3 et SPDX 3.0 JSON-LD
- Format de sortie HTML interactif avec filtres dynamiques, tri par colonnes et export CSV intégré
- Visionneuse SBOM interactive dans l'interface graphique (onglet 9)
- Sous-commandes `diff` et `merge` pour comparer et fusionner des fichiers SBOM
- Politiques CI/CD configurables pour l'intégration continue
- Support de la signature et vérification SBOM via cosign
- Aide contextuelle (❓) sur tous les panneaux de l'interface graphique
- Support des archives `.tar.gz` et `.tgz` comme sources d'images OCI locales
- Scan des répertoires Python `dist-info` et npm `node_modules` via le backend skopeo
- Scan des JARs Maven dans le backend skopeo

### Fixed
- skopeo ne retournait aucun paquet RPM (chemin `--dbpath` incorrect)
- Onglets de l'interface graphique maintenant scrollables pour éviter le chevauchement de texte

## [1.0.0] - 2026-06-22

### Added
- Interface graphique Flutter avec 8 onglets : configuration, résultats, Grype, diff/merge, CI/CD, cosign, historique, filtrage par date
- Génération SBOM pour images OCI (containers) via les backends skopeo et trivy
- Format de sortie HTML statique
- Filtrage par champs de date dans l'interface graphique
- Intégration Grype pour l'analyse des vulnérabilités CVE
- Support des paquets `.deb` (Debian/Ubuntu)
- Support des archives `.zip`
- Support des fichiers `requirements.txt` (Python)
- `LicenseNormalizer` : normalisation des identifiants SPDX de licences
- `ArchiveHelpers` : extraction et inspection d'archives
- Format de sortie Markdown
- Documentation complète en AsciiDoc (`doc/usage.adoc`, `doc/developer.adoc`)
- Fichier spec RPM pour l'empaquetage (`sbom_generator.spec`)

### Changed
- Migration de la documentation de Markdown vers AsciiDoc
- Refactorisation des générateurs CycloneDX et SPDX vers des classes dédiées

## [0.1.0] - 2026-04-28

### Added
- Initialisation du projet
- Génération SBOM à partir d'une liste de paquets RPM
- Formats de sortie : CycloneDX 1.5, SPDX 2.3, JSON personnalisé
- Résolution des dépendances via `rpm requires/provides`
- Support des métadonnées : nom, version, licence, description, fournisseur, checksum
