# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- `sbom-generator scan` : nouveaux formats de sortie `markdown`, `asciidoc` et
  `pdf` (`-f`, écrits via `-o`) — un **rapport de synthèse inter-scanners** :
  résumé global (scanners exécutés, CVE uniques tous scanners confondus, total
  brut), répartition par sévérité pour chaque scanner, et matrice « CVE ×
  scanner » (✓/—) triée par sévérité (identifiants `DEBIAN-CVE-…` d'OSV-Scanner
  normalisés avant comparaison). `pdf` = `asciidoc` + `asciidoctor-pdf` (si
  absent, le `.adoc` est conservé). Ces formats retournent `0` dès qu'un
  rapport est produit, quel que soit le nombre de CVE.
- `scripts/build-dist.sh` scanne désormais le SBOM généré avec Grype +
  OSV-Scanner + Trivy et dépose un PDF de synthèse à côté de l'archive
  (`…-scan-report.pdf` ; avec `--rpm`, aussi `…-rpms-scan-report.pdf`).
  Best-effort : chaque scanner absent est omis, l'absence totale de scanner ou
  d'`asciidoctor-pdf` n'échoue pas le build.

### Added
- `--sdk-version <sdk>=<version>` (répétable) : renseigne la vraie version d'un
  SDK Dart/Flutter. Double effet — (1) applique la version aux paquets
  `source: sdk` correspondants d'un `pubspec.lock` / `pubspec.yaml` (que `pub`
  note toujours `0.0.0`) ; (2) ajoute chaque SDK à la toolchain du SBOM :
  `metadata.tools.components` (CycloneDX, `type: platform`),
  `creationInfo.creators` (SPDX 2.3), éléments `Tool` (SPDX 3.0) — c'est là
  qu'apparaît la version de `dart`, qui n'a pas de paquet dans le lockfile.
  `scripts/build-dist.sh` le passe automatiquement depuis `flutter --version` /
  `dart --version`.

### Fixed
- `pubspec.lock` / `pubspec.yaml` : les paquets `source: sdk` autres que le
  premier (`sky_engine`, `flutter_web_plugins`…) étaient renommés `flutter`
  (via le `description:` scalaire) puis dédupliqués → composants perdus dans le
  SBOM. Le nom est désormais la clé du bloc. Leur version factice `0.0.0` du
  lockfile est aussi omise (PURL `pkg:pub/flutter` sans version) — sauf
  `--sdk-version`. Effet de bord : plus de faux positifs Grype sur
  `flutter@0.0.0` faute de version aberrante.
- `sbom-generator scan --scanner grype` invoque désormais Grype avec les mêmes
  options que l'onglet Grype de la GUI (`--add-cpes-if-none --by-cve --platform
  linux`). Sans `--add-cpes-if-none`, Grype ne matchait que par PURL et
  manquait les CVE indexées par CPE (ex. `flutter@0.0.0` d'un `pubspec.lock`) :
  `scan` rapportait 0 CVE là où la GUI en trouvait. `--by-cve` aligne aussi les
  identifiants (CVE vs GHSA) avec OSV-Scanner / Trivy pour la matrice
  inter-scanners.
- CycloneDX : `license.id` n'est plus attribué qu'aux identifiants réellement
  présents sur la SPDX License List (nouvel instantané `lib/spdx_license_ids.dart`).
  L'ancienne heuristique « le token contient un tiret suivi d'un chiffre » faisait
  passer en `license.id` les raccourcis `debian/copyright` (`GFDL-NIV-1.3`,
  `BSD-3-clause-Berkeley`, `GPL-2.0-only+-with-link-exception`…), produisant un SBOM
  rejeté par la validation de schéma CycloneDX (score sbomqs `sbom_schema_valid` à 0).
  Ces valeurs sont désormais portées en `license.name`. Même durcissement pour les
  termes d'une expression SPDX (SPDX 2.3 / 3.0), escortés en `LicenseRef-…` s'ils ne
  sont pas SPDX-listés.
- Backend OCI syft : le mainteneur dpkg/apk (`metadata.maintainer`) et
  l'architecture (`metadata.architecture`, clé en minuscules) sont désormais lus —
  ils étaient ignorés car le code ne testait que des clés en casse Pascal
  (`Vendor`, `Architecture`). Le SBOM d'une image OCI analysée via syft porte donc
  maintenant un `supplier` de composant (métrique sbomqs `comp_with_supplier`) et
  l'`arch` dans le PURL des paquets Debian/Alpine.

## [1.4.0] - 2026-09-06

### Added
- Backend OCI **cdxgen** (`--oci-tool cdxgen`, ou sélecteur « cdxgen » dans la GUI) en plus
  de `syft`, `trivy` et `skopeo` : lance `cdxgen --type docker` (OWASP CycloneDX Generator,
  requiert Node.js) et normalise le BOM produit — seuls les composants porteurs d'un PURL
  d'écosystème réel sont retenus (`pkg:deb`, `pkg:rpm`, `pkg:apk`, `pkg:pypi`, `pkg:npm`,
  `pkg:golang`, `pkg:maven`…), l'inventaire fichier par fichier de cdxgen (`pkg:generic` de
  type `file`), ses actifs cryptographiques et ses dépôts APT sont écartés pour un résultat
  cohérent avec les autres backends. Registre, archive tar et OCI layout directory sont
  acceptés. L'OS de base est reconstitué depuis le qualifiant `distro=` des PURL système
  (cdxgen n'émet pas de composant `operating-system` dédié)
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
