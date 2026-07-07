# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Support de CycloneDX 1.7 en plus de 1.6 (`--cyclonedx-version`) : classification TLP
  (`--tlp`), déclarations de brevets par paquet (`--patent-map`) et attribution automatique
  des données de composants à l'outil source (`citations`, ex. syft/trivy avec `--image`)
- `--input` accepte désormais des fichiers `.jar` (coordonnées Maven via `pom.properties`,
  `META-INF/MANIFEST.MF`, ou nom de fichier) et des dossiers scannés récursivement pour
  tous les types de paquets/manifestes déjà supportés ; sélecteur de dossier ajouté dans
  la GUI Flutter
- Un `.jar` « shaded »/uber-jar embarquant des dépendances relocalisées (chacune avec son
  propre `pom.properties`, ex. `netty-common-*.jar` qui embarque `org.jctools:jctools-core`)
  produit désormais un composant SBOM par dépendance détectée, en plus du jar lui-même —
  comportement aligné sur syft, vérifié sur deux jeux réels de 207 et 274 jars
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
- GUI : le tableau « Comparaison inter-scanners » du tableau de bord n'affichait que les
  CVE vues par au moins 2 scanners sur 3, masquant celles détectées par un seul scanner —
  il liste désormais l'union complète des CVE (Grype ∪ OSV ∪ Trivy), avec un marqueur
  visuel (bordure/icône ambre) sur les CVE vues par un seul scanner pour repérer les
  écarts de détection entre outils
- `.jar` sans `pom.properties` (la grande majorité des jars réels, hors builds Quarkus/RH)
  étaient silencieusement ignorés : `JarParser` lit désormais `META-INF/MANIFEST.MF`
  (`Bundle-SymbolicName`, `Implementation-Vendor-Id`, `Implementation-Title`,
  `Automatic-Module-Name`) et, à défaut, retombe sur `groupId = artifactId` plutôt que
  d'abandonner le paquet — sur un jeu réel de 207 jars, 82 étaient perdus par rapport à
  syft, 0 après ce correctif
- `.jar` « shaded »/uber-jar embarquant le `pom.properties` d'une dépendance relocalisée
  (ex. `netty-common-*.jar` qui embarque aussi celui de `org.jctools:jctools-core`)
  ressortait avec l'identité de la dépendance embarquée au lieu de la sienne : `JarParser`
  lit désormais chaque `pom.properties` embarqué individuellement (jamais concaténé), pour
  éviter tout mélange — détecté par comparaison avec syft sur un second jeu réel de 274 jars
- skopeo ne retournait aucun paquet RPM (chemin `--dbpath` incorrect)
- Onglets de l'interface graphique maintenant scrollables pour éviter le chevauchement de texte
- CLI : `--input` pointant directement vers une archive unique (`.zip`, `.tar`,
  `.tar.gz`, `.tgz`, `.whl`, `.deb`, `.rpm`) provoquait un crash
  (`FileSystemException` de décodage UTF-8) au lieu d'être traité comme le
  paquet à analyser ; message d'erreur explicite pour les autres cas de
  fichier illisible
- GUI : les champs *Fichier de paquets* et *Image OCI* sont désormais
  mutuellement exclusifs — remplir l'un vide automatiquement l'autre (saisie,
  glisser-déposer, sélecteur de fichier/répertoire), pour éviter toute
  ambiguïté sur la source réellement utilisée

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
