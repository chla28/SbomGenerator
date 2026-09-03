# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- `scripts/build-dist.sh` génère désormais un SBOM CycloneDX (`sbom.cdx.json`, dépendances
  runtime de la GUI) et l'inclut dans l'archive de distribution, auto-hébergement via le
  binaire `sbom-generator` tout juste compilé par le script ; avec `--rpm`, un second SBOM
  décrivant les RPM effectivement construits est produit à côté de l'archive
- Backend OCI skopeo : les paquets Debian/Ubuntu extraient désormais leur licence depuis
  `/usr/share/doc/<paquet>/copyright` (format DEP-5 machine-readable) au lieu de toujours
  rapporter une licence vide — `LicenseNormalizer` reconnaît en plus les noms courts
  propres à Debian (`GPL-2+`, `Expat`, `public-domain`, `GFDL-1.3`…)
- GUI : aide en ligne — un bouton ❓ dans la barre du haut ouvre le manuel utilisateur
  complet directement dans l'application (sommaire des 21 chapitres à gauche, contenu à
  droite, renvois internes cliquables, recherche par titre et par contenu avec extrait de
  contexte), en plus de l'aide contextuelle courte déjà présente sur chaque champ/section

### Fixed
- Documentation GUI : deux renvois internes de `user.adoc` (vue JSON, vue Template)
  s'affichaient sans texte lisible (`[sec-vue-json]`) faute de texte de lien explicite
- CycloneDX : les licences distinguent désormais la valeur *declared* (brute, telle que
  rapportée par le paquet) de la valeur *concluded* (normalisée SPDX par
  `LicenseNormalizer`), via le champ `license.acknowledgement` (CycloneDX 1.5+) — une
  licence composée en AND pur (ex. `GPL-2.0-or-later AND BSD-3-Clause`) est éclatée en
  autant d'entrées `concluded` individuelles. Améliore la qualité mesurée par `sbomqs`
  (catégorie Licensing) sans rien inventer : la donnée existait déjà, elle est juste mieux
  exposée. `SbomReader` relit la valeur brute complète depuis l'entrée `declared`
- SPDX 2.3 / SPDX3 : `LicenseNormalizer.toSpdxExpression` échappe désormais tout terme non
  reconnu comme identifiant SPDX réel (ex. `curl`, `permissive`, `public-domain` — noms
  courts propres à `debian/copyright`) en `LicenseRef-<slug>`, pour que l'expression
  produite reste syntaxiquement valide au sens de la grammaire SPDX même sur ces noms
  Debian non listés
- GUI : l'export du Tableau de bord (AsciiDoc/PDF) inclut désormais une note explicative sur
  les écarts de détection entre scanners propres aux paquets système (Debian/Alpine/RPM) :
  OSV-Scanner pouvant tomber à 0 CVE en mode scan de SBOM, et l'écart d'exhaustivité entre
  Grype et Trivy sur les avis Debian

## [1.3.0] - 2026-09-03

### Added
- GUI : les exports PDF (Tableau de bord, Grype, OSV-Scanner, Trivy) indiquent désormais la
  version de sbom_generator_gui et celle du ou des scanner(s) concerné(s) (détectées via
  `<outil> --version` au moment de l'export)

## [1.2.1] - 2026-09-03

### Fixed
- GUI : dans le Tableau de bord, un CVE préfixé par OSV-Scanner selon l'origine de l'avis
  distro (ex. `DEBIAN-CVE-2026-13221`) n'est plus compté comme distinct du même CVE nu
  (`CVE-2026-13221`) rapporté par Grype/Trivy dans la comparaison inter-scanners

## [1.2.0] - 2026-09-03

### Added
- GUI : les exports PDF (Tableau de bord, Grype, OSV-Scanner, Trivy) utilisent désormais un
  thème `asciidoctor-pdf` calqué sur l'appli — badges de sévérité colorés, barre de
  répartition par sévérité, en-têtes de tableau bleus — au lieu du rendu noir et blanc
  par défaut

## [1.1.0] - 2026-08-31

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
- Un SBOM CycloneDX/SPDX généré depuis une image de conteneur (`--image`, backends
  syft/trivy) n'identifiait jamais l'OS de base — Trivy en mode `trivy sbom` ignorait
  alors silencieusement toute la classe de vulnérabilités « os-pkgs » (paquets système
  RPM/DEB/APK), même si chaque paquet portait déjà `distro=...` dans son propre purl :
  sur une image Keycloak (UBI 9) réelle, `trivy sbom` ne retrouvait que 146 CVE contre
  253 pour `trivy image` sur la même image (101 CVE `os-pkgs` manquantes). `OciParser`
  extrait désormais l'OS de base (`distro` de syft, `Metadata.OS` de trivy) et
  `CycloneDxGenerator`/`SpdxGenerator`/`Spdx3Generator` ajoutent un composant dédié
  (`type: "operating-system"` / `primaryPackagePurpose: "OPERATING-SYSTEM"`). Deux
  exigences non documentées de Trivy, isolées par bissection : le nom doit suivre sa
  taxonomie interne (`redhat`, pas `rhel` comme chez syft — table de correspondance
  ajoutée) et, côté SPDX, le SPDXID doit être préfixé `SPDXRef-OperatingSystem-` (pas
  `SPDXRef-Package-`). Backend skopeo non couvert (ne lit pas `/etc/os-release`).
- Les modules « core » de Spring Framework (`spring-core`, `spring-webmvc`, `spring-tx`…)
  extraits d'un `.jar` recevaient un groupId erroné (`spring.core` au lieu du vrai
  `org.springframework`, déduit à tort d'un `Automatic-Module-Name` qui n'est pas un
  groupId Maven) — impact sécurité réel : un scanner de vulnérabilités ne peut pas
  associer de CVE à un mauvais groupId, ce qui masquait silencieusement des CVE non
  corrigées (CVE-2025-41249, CVE-2024-38820, CVE-2025-22233, entre autres, sur
  `org.springframework:spring-core`). `JarParser` applique désormais une table de
  correspondance curée (`_knownGroupIdOverrides`) pour les ~22 modules officiels de
  Spring Framework, avant l'heuristique manifeste
- Les composants Maven du SBOM CycloneDX pliaient le groupId dans le champ `name`
  (`"groupId:artifactId"`) au lieu d'utiliser le champ `group` dédié prévu par le schéma —
  contrairement à syft/trivy. `cyclonedx_generator.dart` sépare désormais `group`/`name`,
  et `sbom_reader.dart` recombine les deux à la relecture (`convert`, `merge`) pour ne pas
  perdre le groupId
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
