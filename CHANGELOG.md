# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

🇫🇷 **Français** · 🇬🇧 [English](CHANGELOG.en.md)

## [Unreleased]

## [1.6.4] - 2026-10-05

### Changed
- **Packaging** : la licence du paquet RPM est `LGPL-3.0-only` (elle indiquait `MIT`), `LICENSE` et `COPYING` sont livrés dans l'archive et les RPM (`%license`) ; descriptions du RPM et de `pubspec.yaml` mises à jour ; suppression du fichier de test visuel jetable `gui/test/_visual_check_vuln_table.dart`.

### Fixed
- **CLI — options obligatoires** (`cra --sbom`, `convert`/`licenses --input`, `merge --output`) : leur absence affiche une erreur d'usage (`cra: L'option --sbom est obligatoire.`) et sort en code 1, au lieu d'une exception non rattrapée (code 255).
- **CLI — `--sign` sans `cosign`** (et `--min-quality-score` sans `sbomqs`) : avertissement et poursuite, au lieu d'une `ProcessException` après l'écriture des fichiers.
- **CLI — `scan --cve-after/--cve-before`** : seules les dates `AAAA-MM-JJ` réelles sont acceptées (`2024-13-45`, `2024-02-30`, `2024-1-1` sont refusées au lieu d'être décalées).
- **CLI — résumé « Analysés : X/Y »** : le dénominateur compte tous les paquets visés (références, paquets issus des manifestes, image, objets imbriqués) ; il valait par exemple `7/6` au lieu de `7/8`.
- **CLI — messages d'erreur d'arguments** : les messages du paquet `args` (« is not an allowed value… », « Could not find an option named… ») sont traduits en français.

## [1.6.3] - 2026-10-05

### Added
- **Copies d'écran de la GUI dans les README** (`doc/screenshots/`, français et anglais), générées par `gui/test/screenshot_test.dart` ; sections « Interface graphique » des README.

### Fixed
- **GUI — export AsciiDoc/PDF et CSV des onglets de scan** : le rapport (titres, résumé, tableaux, couches, note de filtre de date) et le champ « oui » des colonnes KEV/PoC restaient en français ; ils suivent maintenant la langue de l'interface. Libellé du champ « Fichier SBOM » d'OSV-Scanner et police des boutons du filtre de date corrigés.

## [1.6.2] - 2026-10-05

### Added
- **Licence LGPL v3** (`LGPL-3.0-only`) : `LICENSE` (LGPL) et `COPYING` (GPL) ; sections *Licence* des README ; ajout de `SECURITY.md`. Retrait des fichiers de travail (`dialogue.txt`, `prompt.txt`, `licences.adoc`) et des deux wheels tierces de `example/3PP/python3`.

## [1.6.1] - 2026-10-05

### Added
- **Projet bilingue FR / EN.** Les messages du CLI, l'aide `--help` et les
  rapports lisibles (synthèse `scan` Markdown/AsciiDoc/PDF, rapport `cra`,
  rapport `licenses`, tableaux HTML/Markdown/AsciiDoc) existent en français et
  en anglais. Langue choisie par `--lang fr|en` (accepté partout, sous-commandes
  comprises), puis la variable `SBOM_LANG`, puis `LC_ALL` / `LC_MESSAGES` /
  `LANG` ; français par défaut (`lib/i18n.dart`, `tr(fr, en)`). Jamais
  traduits : le contenu des SBOM (noms et valeurs de propriétés, descriptions de
  couches), les clés JSON, les identifiants SARIF et la ligne
  `SBOM written → …` lue par la GUI. La GUI transmet sa propre langue au CLI
  qu'elle lance (`SBOM_LANG`).
- **GUI entièrement localisée (français / anglais)** : tous les écrans,
  les rapports exportés (AsciiDoc/PDF/CSV côté GUI), les messages de service et
  l'aide en ligne (`assets/help/manual_en/`, générée depuis
  `gui/doc/user.en.adoc` par `tool/generate_help.dart`) suivent le réglage
  *Langue de l'interface* ; le manuel s'ouvre dans la langue effective.
- Documentation en anglais, tenue à jour en parallèle du français :
  `README.en.md`, `doc/usage.en.adoc`, `doc/developer.en.adoc`,
  `gui/doc/user.en.adoc`, `gui/doc/developer.en.adoc`, `gui/README.en.md`,
  `CHANGELOG.en.md`.

### Changed
- **Rapport JSON de `cra`** : la table `ntiaMinimumElements` est désormais
  indexée par des identifiants stables (`supplierName`, `componentName`,
  `componentVersion`, `otherUniqueIdentifiers`, `dependencyRelationship`,
  `sbomAuthor`, `timestamp`) au lieu de libellés français, et chaque entrée de
  `fieldChecks[]` gagne un `id` stable (`name`, `version`, `supplier`,
  `identifier`, `hash`, `license`) à côté du libellé `field` (désormais
  traduit).
- Messages du CLI qui mêlaient français et anglais (avertissements des
  parseurs, erreurs) harmonisés : chaque message existe dans les deux langues.
- Documentation : l'AsciiDoc (`doc/usage.adoc`, `doc/developer.adoc`) est la
  seule référence ; les doublons `usage.md` et `develop.md` sont supprimés.

## [1.6.0] - 2026-10-02

### Added
- **`--depth` : descente dans les objets imbriqués** (CLI et GUI) — avec
  `--input`, un RPM/deb, une archive tar/tgz/zip, un jar/war/ear ou une wheel
  est ouvert et ce qu'il contient est analysé à son tour : jars d'un RPM,
  paquets et jars d'une archive, jars d'un fat jar, manifestes rencontrés
  (`package-lock.json`, `go.sum`, `pom.xml`…). `--depth 0` (défaut : l'objet
  seul), `N` niveaux, `all` (plafonné à 10). Le SBOM fusionné contient
  l'objet et son contenu (propriétés `sbom_generator:nested:location` /
  `depth`, annotations SPDX, champ `nested` du JSON, arêtes de dépendance
  conteneur → contenu) ; un SBOM par objet imbriqué est écrit à côté de `-o`
  (`<base>.nested-NN-<objet>.<ext>`, `--no-nested-files` pour s'en passer).
  Extraction sélective par script Python embarqué (rpm, deb, zip, tar — sans
  `rpm2cpio`/`cpio`/`dpkg-deb`), bornée en taille et en nombre de fichiers
  (`lib/nested_archive.dart`). `.war` / `.ear` sont désormais reconnus comme
  les `.jar`. GUI : sélecteur *Profondeur* et case *Un SBOM par objet
  imbriqué* sous le champ d'entrée.
- **`scan --package <fichier> [--depth N]`** : scanne directement un RPM, deb,
  tgz, zip, jar… (SBOM généré avec la profondeur demandée, puis soumis à
  Grype / OSV-Scanner / Trivy) ; chaque CVE est rattachée à l'objet qui
  contient le paquet vulnérable (colonne `OBJET`, clé interne `container`),
  y compris avec `--sbom` sur un SBOM produit par `--depth`. GUI : nouvelle
  source *Paquet / archive* (avec profondeur) dans les trois onglets de scan.

### Changed
- `scan` : l'erreur de sélection de source cite désormais `--package` en plus
  de `--sbom` et `--image` (« exactement l'un des trois »).
- `Package.copyWith` accepte `sourceRef` (utilisé pour les chemins logiques
  des objets imbriqués).

## [1.5.16] - 2026-09-29

### Fixed
- **GUI — rapport du tableau de bord** : la section « Détail des CVE » ne
  suivait pas le seuil de sévérité choisi (elle restait limitée à
  KEV / EPSS ≥ 10 % / Critical-High, même avec « All » ou « ≥ Medium »). Elle
  reprend désormais toutes les CVE retenues par le seuil et s'intitule
  « Détail des CVE » (ex-« Détail des CVE prioritaires »).

## [1.5.15] - 2026-09-29

### Added
- **`licenses --format`** : le rapport de licences peut aussi être produit
  en Markdown, HTML (autonome), CSV ou JSON (`-f asciidoc|markdown|html|csv|json`,
  AsciiDoc par défaut). Avec `-f json`, `-o` est facultatif (JSON sur la
  sortie standard). L'analyse (regroupement, catégories copyleft) est
  désormais séparée du rendu (`LicenseReportGenerator.analyze` / `render`).
- **GUI — onglet Licences** : visualise les licences du SBOM sélectionné
  (vue *Par licence* dépliable ou *Tableau* triable, badges copyleft
  fort/faible et « sans licence », filtre par licence ou paquet) ; le
  rapport en bas de page se génère au choix en AsciiDoc, Markdown, HTML,
  CSV ou JSON. Les données viennent de `licenses -f json` (aucune
  classification côté GUI).
- **GUI — localisation français / anglais (début)** : infrastructure
  `gen-l10n` (fichiers ARB `gui/lib/l10n/`, français comme référence,
  pluriels ICU), menu *Langue de l'interface* (Système / Français /
  English, mémorisé, repli sur le français). Traduits : composants communs
  aux onglets de scan (tableau, filtres, sources, analyse par couche, popup
  CLI) et onglet Grype. Les autres écrans, les rapports exportés, l'aide et
  le CLI suivront.

## [1.5.14] - 2026-09-27

### Added
- **GUI, Tableau de bord — niveau de sévérité du rapport PDF** : menu
  *Critical* / *≥ High* / *≥ Medium* / *All* (défaut *All*, mémorisé) à
  côté du bouton d'export. Tout le rapport (résumé, répartition par
  scanner, couches, comparaison inter-scanners, détail) porte sur les CVE
  retenues, d'après leur pire sévérité tous scanners confondus ; les CVE
  CISA KEV sont toujours incluses. Le rapport filtré l'indique en tête.

## [1.5.13] - 2026-09-26

### Added
- **CI GitHub Actions** (`.github/workflows/ci.yml`) : analyse statique et
  tests du CLI et de la GUI sur chaque push vers `main` et chaque pull
  request, puis build Linux (`dart compile exe`, `flutter build linux
  --release`, artefacts conservés 7 jours). SDK figés sur ceux du
  développement (Dart 3.13.4, Flutter 3.47.5).
- **Release automatique sur tag `vX.Y.Z`** (`.github/workflows/release.yml`)
  : `build-dist.sh --rpm` dans un conteneur AlmaLinux 9 (binaires et RPM
  compatibles RHEL 9 / 10 et Fedora récentes), rapports CVE PDF (grype,
  osv-scanner, trivy), publication de l'archive, des RPM, des SBOM et des
  rapports dans une GitHub Release dont les notes sont la section du
  CHANGELOG ; échec si le tag ne correspond pas à `pubspec.yaml`.

### Changed
- Les archives de test `example/3PP` (1,1 Mo) sont versionnées : les tests
  d'intégration tar/zip tournent aussi en CI.

## [1.5.12] - 2026-09-26

### Added
- **GUI — bouton « CLI Commande »** dans les onglets Grype, OSV-Scanner et
  Trivy : popup affichant, avec bouton Copier, la commande native exacte
  correspondant au paramétrage de l'onglet (séquence réelle — génération
  des SBOM de couche puis scan(s) — avec l'option *Par couche*) et
  l'équivalent `sbom-generator scan` (options par couche, filtre de date,
  `--no-enrich`), avec la liste des options non transposables. Les
  arguments des scanners sont désormais construits par
  `GrypeRunner/OsvRunner/TrivyRunner.buildArgs`, partagés entre
  l'exécution et l'aperçu.

## [1.5.11] - 2026-09-26

### Added
- **Vulnérabilités par couche d'image** — CLI : `scan --per-layer`, avec
  `--layer-scan attribute|each` :
  - `attribute` (défaut) : un scan du SBOM global, chaque CVE rattachée à la
    couche d'origine de son paquet (`sbom_generator:layer:index`) ;
  - `each` : le SBOM de chaque couche est scanné (CVE d'une version
    remplacée plus haut dans la pile incluses).
  `scan --image <image>` (exclusif de `--sbom`, avec `--oci-tool` et
  `--layer-mode`) génère le SBOM — et les SBOM de couche — dans un
  répertoire temporaire avant de le scanner. Sortie texte : colonne
  `COUCHE` + tableau « CVE par couche » ; SARIF : propriété `layer` ;
  rapports markdown/asciidoc/pdf : section « Couches de l'image » et
  colonne « Couche(s) ». Nouveau module `lib/layer_scan.dart`.
- **GUI** : option *Par couche* (Rattachement / Chaque couche,
  Métadonnées / Rootfs) dans les onglets Grype, OSV-Scanner et Trivy en
  mode image ; en rattachement, la couche native de Trivy (`Layer.DiffID`)
  et d'OSV-Scanner (`image_origin_details`) est prioritaire. Tableau :
  colonne *COUCHE*, filtre par couche, regroupement par couche (en-têtes
  avec instruction et compteurs), exports CSV/PDF avec couches. Tableau de
  bord : carte *Couches de l'image*, colonne *COUCHE(S)* dans la
  comparaison inter-scanners, section dans l'export PDF.

## [1.5.10] - 2026-09-26

### Added
- **`--per-layer` : un SBOM par couche d'image** (avec `--image`), en plus
  du SBOM global, dans chaque format demandé :
  `<base>.layer-NN-<digest12>.<ext>`. Le SBOM d'une couche décrit son
  *delta* (composants ajoutés/modifiés, supprimés listés à part) ; son
  composant racine porte le digest et l'instruction de build de la couche.
  Le SBOM global indique la couche d'origine de chaque composant
  (`sbom_generator:layer:index`/`:digest`/`:modifiedBy`) et référence chaque
  SBOM de couche (BOM-Link CycloneDX, résumé `sbom_generator:layers:NNN`) ;
  SPDX 2.3/3.0 : commentaire de document + annotations ; Markdown, AsciiDoc,
  HTML, CSV : colonne « Couche » / « Changement » et composants supprimés.
  Le global est écrit en premier.
- **`--layer-mode metadata|rootfs`** :
  - `metadata` (défaut, syft/trivy) : couche d'origine indiquée par le
    backend — `Layer.DiffID` de trivy ; pour syft, seconde analyse
    `--scope all-layers` et couche la plus basse où le paquet apparaît
    (l'analyse habituelle rattache tous les paquets système à la dernière
    couche qui a réécrit la base rpm/dpkg/apk). Ajouts uniquement.
  - `rootfs` (les quatre backends, seul mode pour skopeo/cdxgen) : couches
    appliquées une à une sur un rootfs cumulé (overlayfs, *whiteouts*
    compris, sans jamais suivre de lien symbolique), rootfs réanalysé après
    chaque couche — ajouts, modifications (montée de version…),
    suppressions. Une image de registre est copiée via skopeo, avec repli
    sur le stockage local podman/Docker.
- Nouveau module `lib/image_layers.dart` ; `OciParser.layerAttribution`,
  `rootfsLayerAnalysis`, `scanRootfs`.
- **GUI** : case « Un SBOM par couche » + choix Métadonnées/Rootfs sous le
  backend OCI ; navigation *SBOM global / couche N* (instruction, compteurs,
  supprimés) dans l'Arborescence et la Visionneuse ; colonne
  Couche/Changement dans la Visionneuse, regroupement « Couche » dans
  l'Arborescence. Les SBOM de couche sont exclus des sélections
  automatiques et du menu « Générés ».

### Changed
- GUI, Arborescence : boutons « tout déplier / replier » en icônes avec
  info-bulle (la barre débordait avec le segment « Couche »).

## [1.5.9] - 2026-09-18

### Added
- **GUI — champ « Binaire autonome » (`--binary`)** : la GUI n'exposait pas
  ce nouveau flag CLI (v1.5.8). Ajout d'un troisième champ dans la section
  *Entrée*, sous un second séparateur « OU », mutuellement exclusif avec
  *Paquets à analyser* et *Image OCI* (les trois se vident l'un l'autre).
  Ne propose pas le sélecteur *Outil OCI* (`--binary` force `--oci-tool
  syft` côté CLI) ; affiche à la place un rappel textuel. `SbomConfig`
  gagne le champ `binaryPath` (persistant, profils inclus).

## [1.5.8] - 2026-09-17

### Added
- **`--binary <fichier>` / `-b`** : analyse directe d'un binaire autonome
  (ex. exécutable Go lié statiquement), sans registre ni conteneur. Alias
  explicite pour `--image <fichier>` (déjà fonctionnel : syft détecte
  automatiquement qu'un chemin local existant est une source fichier), qui
  force `--oci-tool syft` et refuse toute combinaison avec `--oci-tool
  trivy|skopeo|cdxgen` ou avec `--image`.
  - **Go** (statique ou non) : liste complète des modules + versions lue
    depuis les métadonnées `buildinfo` embarquées (`go-module-binary-cataloger`
    de syft), même sur un exécutable strippé.
  - **Autres langages** (Rust, C/C++ statiques…) : seul le classifieur
    générique de syft s'applique — un catalogue *fixe* de bibliothèques
    open source connues (OpenSSL, zlib, sqlite, busybox…), pas une
    extraction arbitraire. Une bibliothèque sans signature connue ni
    métadonnée embarquée n'est pas récupérable après coup.
- Nouvelle valeur d'enum `OciRefType.binary` (`lib/oci_parser.dart`) :
  corrige au passage le libellé console trompeur affiché quand `--image`
  pointait déjà sur un fichier local (« Analyse de l'image OCI (registre) »
  alors qu'aucun registre n'était interrogé).

## [1.5.7] - 2026-09-09

### Added
- **Empreinte des paquets RPM installés** : `%{SIGMD5}` (le « pkgid » RPM —
  MD5 de l'en-tête + payload, identité de contenu native, aussi utilisée par
  Trivy) est émis comme empreinte `MD5` du composant. Auparavant un SBOM
  généré depuis une liste de noms RPM installés ne portait aucune empreinte
  (seul un fichier `.rpm` passé en chemin donnait un SHA-256 / SHA-512).
  Le `%{SHA256HEADER}` reste exposé à part (`rpm:header-sha256`).

## [1.5.6] - 2026-09-09

### Added
- **Empreintes cryptographiques des composants** (`Package.hashes`) émises
  dans les trois formats : CycloneDX (`hashes`), SPDX 2.3 (`checksums`),
  SPDX 3.0 (`verifiedUsing`). Collecte opportuniste, sans requête réseau :
  - `integrity` des lockfiles npm / yarn v1 (SRI base64 → hexadécimal) et
    `sha256` de `pubspec.lock` ;
  - champ `Digest` de Trivy et digests d'artefact de Syft (`archiveDigests`
    / `digest`, ex. JAR) lors de l'analyse d'images OCI ;
  - `hashes` des composants produits par cdxgen ;
  - calcul SHA-256 + SHA-512 des fichiers `.rpm` / `.deb` / `.jar` / `.whl`
    fournis directement en entrée.
  Seuls les condensats hexadécimaux d'un artefact réel sont retenus ; les
  formats dérivés (dirhash Go `h1:`, checksum APK `Q1…`) sont écartés.
- Le condensat de l'en-tête RPM (`%{SHA256HEADER}`), auparavant émis à tort
  comme empreinte d'artefact `SHA-256` du composant CycloneDX, est désormais
  exposé comme propriété/annotation dédiée `rpm:header-sha256` (ce n'est pas
  le hash du fichier `.rpm`).
- Nouvelle dépendance : `package:crypto` (calcul des empreintes de fichiers).
- **Fournisseur des composants npm** : le champ `author` de chaque
  `package.json` installé dans `node_modules` est lu (le `package-lock.json`
  ne le contient pas). Sans arbre `node_modules`, comportement inchangé.
- **`--supplier "<nom>"`** (génération et `convert`) : valeur de repli pour
  le fournisseur des composants dont la source ne porte aucun éditeur
  (lockfiles Go / npm / yarn / pip / pub, `requirements.txt`). N'écrase
  jamais un fournisseur détecté (`%{VENDOR}` RPM, `Maintainer` Debian,
  `groupId` Maven…). Le champ `supplier` est obligatoire dans BSI
  TR-03183-2 (rapport `cra`).

### Changed
- **SPDX 2.3** : le champ `supplier` d'un composant est désormais **toujours
  présent** — `Organization: <fournisseur>` si connu, sinon `NOASSERTION`
  (valeur explicite demandée par la spéc, prise en compte par les éléments
  minimaux NTIA et `sbomqs`) au lieu d'être omis. Idem pour le paquet OS.
- `Package` expose `copyWith({license, vendor})` ; `_applyLicenseOverrides`
  s'appuie dessus (plus de reconstruction manuelle par type).
- `convert` : un `supplier` valant `NOASSERTION` dans un SBOM SPDX 2.3 source
  est relu comme « inconnu » (chaîne vide) au lieu d'être recopié tel quel
  comme nom de fournisseur.

### Fixed
- Lecteur SPDX 3.0 (`convert -i <fichier>.spdx3.jsonld`) : le filtre de type
  attendait `software_Package` alors que le générateur (et `diff`) émettent
  `software:Package`, et les champs `software:packageVersion` /
  `software:downloadLocation` n'étaient pas lus — `convert` depuis un SBOM
  SPDX 3.0 renvoyait un document **vide**. Types et champs alignés (les deux
  formes de préfixe sont tolérées), licence `NOASSERTION` désormais relue
  comme vide, empreintes `verifiedUsing` relues.

### Notes
- Pour un SBOM issu d'une image OCI, la plupart des paquets système restent
  sans empreinte : ils sont installés dans l'image, pas présents sous forme
  d'artefact, et ni Syft ni Trivy ne reconstruisent leur condensat. La
  couverture s'améliore surtout pour les paquets applicatifs et, via Trivy,
  une partie des RPM.

## [1.5.5] - 2026-09-09

### Added
- **Rapport de conformité Cyber Resilience Act** — nouvelle sous-commande
  CLI `sbom_generator cra --sbom <fichier>` et nouvel onglet *Conformité CRA*
  dans la GUI. Évalue un SBOM contre le **sous-ensemble d'exigences du
  Règlement (UE) 2024/2847 vérifiables automatiquement**, clairement délimité :
  - *format et complétude du SBOM* — format d'usage courant lisible par
    machine et couverture des dépendances (Annexe I §2 point 1), champs de
    données par composant (BSI TR-03183-2 : nom, version, fournisseur,
    identifiant unique PURL/CPE, empreinte, licence), éléments minimaux
    NTIA 2021 ;
  - *gestion des vulnérabilités* — inventaire des vulnérabilités connues et
    disponibilité des correctifs (Annexe I §2 points 1-2), via `--scan` ;
  - *vulnérabilités activement exploitées* — toute CVE au catalogue CISA KEV
    est signalée comme déclenchant la notification à l'ENISA sous 24 h
    (art. 14).
  - Métadonnées fabricant/produit depuis un fichier `cra.yaml`, des options
    (`--manufacturer`, `--product`, `--product-version`, `--support-until`,
    `--vuln-contact`, `--cvd-policy-url` ; priment sur le fichier) ou, à
    défaut, `metadata.component` du SBOM.
  - Sorties `--format pdf` (même charte que le rapport `scan`), `asciidoc`
    ou `json` (schéma `sbom-generator/cra-report/1`). Code de retour `2` si
    non conforme (format non lisible par machine, champ obligatoire manquant,
    vulnérabilité sans correctif, CVE activement exploitée).
  - Les autres obligations du CRA relèvent du fabricant : elles sont listées,
    non évaluées. **Le rapport n'est pas une déclaration de conformité.**

## [1.5.4] - 2026-09-08

### Changed
- **Rapports PDF** (GUI : tableau de bord et onglets Grype / OSV / Trivy ;
  CLI : `scan --format pdf|asciidoc`) — refonte visuelle :
  - page de garde (titre, sous-titre, date en toutes lettres, cible analysée) ;
  - *résumé exécutif* : encart chiffré « Critiques / Élevées / CISA KEV /
    EPSS ≥ 10 % » et un verdict d'une phrase (action immédiate requise si des
    CVE KEV sont présentes, action prioritaire si des critiques, etc.) ;
  - thème sobre : police sans-serif (`default-sans` d'asciidoctor-pdf, sans
    police embarquée), palette bleu-ardoise, en-têtes de tableau foncés,
    pied de page « titre du rapport … Page X / Y » avec filet ;
  - libellés de sévérité en français (CRITIQUE / ÉLEVÉE / MOYENNE / FAIBLE).
  - GUI : la *cible analysée* (chemin du SBOM ou référence d'image) est
    remontée depuis les onglets de scan jusqu'à l'en-tête du rapport.

## [1.5.3] - 2026-09-08

### Fixed
- `scripts/build-dist.sh` et `scripts/build-rpm-mock.sh` : la version par
  défaut est désormais lue depuis le champ `version:` de `pubspec.yaml` au
  lieu d'être figée à `1.4.0` — l'archive et les RPM portent la bonne
  version même sans passer l'argument `VERSION`.

## [1.5.2] - 2026-09-08

### Added
- **GUI** — clic sur un numéro de CVE (tableau de bord *et* onglets Grype /
  OSV-Scanner / Trivy) : la ligne se déplie et affiche le détail complet de
  la CVE — paquet & versions, sévérité et dates telles que rapportées par
  chaque scanner, exploitabilité détaillée (CISA KEV avec date d'ajout /
  échéance / rançongiciel, EPSS + percentile, sous-score CVSS + vecteur +
  maturité, liens PoC cliquables), et boutons de référence vers NVD /
  CVE.org / osv.dev / CISA KEV. Nouveau widget partagé
  `gui/lib/widgets/cve_detail.dart`.
- **GUI**, export PDF / AsciiDoc du tableau de bord : nouvelle section
  « Détail des CVE prioritaires » — un bloc par CVE au catalogue CISA KEV,
  ou EPSS ≥ 10 %, ou de sévérité Critical / High.

### Changed
- **GUI**, tableau de bord : le tableau « Comparaison inter-scanners » est
  maintenant triable par colonne — sévérité, CVE / ID, présence par scanner
  (Grype / OSV / Trivy, ✓ avant —), et CISA KEV / score EPSS quand
  l'enrichissement a tourné. En-têtes cliquables (clic = trier, re-clic =
  inverser). Le tri par défaut est inchangé (priorisation par risque :
  KEV → EPSS → sévérité si enrichissement, sinon sévérité). L'export
  AsciiDoc / PDF suit désormais l'ordre affiché.

## [1.5.1] - 2026-09-08

### Added
- **GUI** — enrichissement exploitabilité dans les onglets de scan (Grype /
  OSV-Scanner / Trivy) et le tableau de bord, aligné sur la ligne de commande :
  - pastilles *KEV* (CISA, rouge), *EPSS*, *PoC* et *expl. CVSS* sous chaque
    ligne de vulnérabilité, colonnes triables *KEV* / *EPSS* ;
  - filtre *CISA KEV (N)* à côté des filtres de sévérité ;
  - bouton ☁ (barre d'outils de la table) pour basculer l'enrichissement en
    ligne / hors-ligne — choix mémorisé (`shared_preferences`), partagé par les
    trois onglets ;
  - colonnes *KEV* / *EPSS* / *PoC* ajoutées aux exports CSV et AsciiDoc/PDF ;
  - le tableau de bord marque et priorise les CVE KEV / EPSS élevé dans sa
    comparaison inter-scanners.
  Nouveau `gui/lib/services/vuln_enrichment.dart` (copie synchronisée du module
  CLI) + `gui/lib/services/scan_enrichment.dart`. Grype exposant KEV/EPSS/CVSS
  nativement, seul le signal PoC déclenche une requête réseau pour cet onglet ;
  cache 24 h partagé avec la CLI sous `~/.cache/sbom-generator/`.

## [1.5.0] - 2026-09-08

### Added
- `sbom-generator scan` : **enrichissement des CVE avec les signaux
  d'exploitabilité et d'exploitation active** (`lib/vuln_enrichment.dart`),
  actif par défaut.
  - **CISA KEV** — la CVE est activement exploitée dans la nature (date
    d'ajout, échéance de remédiation, usage par un rançongiciel) ;
  - **EPSS** (FIRST.org) — probabilité d'exploitation à 30 jours (score +
    percentile) ;
  - **PoC / exploit public** — dépôts recensés par `poc-in-github` +
    maturité `E:` du vecteur CVSS ;
  - **exploitabilité CVSS** — sous-score AV/AC/PR/UI calculé localement.
  Grype fournissant déjà KEV/EPSS/CVSS dans sa base, les requêtes réseau ne
  servent qu'à compléter les CVE vues uniquement par OSV-Scanner / Trivy et à
  récupérer le signal PoC ; réponses mises en cache 24 h sous
  `~/.cache/sbom-generator/`, repli sur le cache en cas de coupure.
- `scan` : nouvelles options `--enrich` / `--no-enrich` (aussi
  `SBOMGEN_OFFLINE=1`), `--no-poc`, `--enrich-timeout`, `--only-kev`,
  `--epss-min <x>` et `--sort severity|risk`.
- `scan --format text` : colonnes `KEV` / `EPSS` / `PoC`. Les alertes
  Critical/High des formats rapport portent les marqueurs `[KEV]`,
  `EPSS <score>`, `[PoC]`.
- Rapport de synthèse (`markdown` / `asciidoc` / `pdf`) : section
  **« Exploitabilité et exploitation active »** — liste des CVE CISA KEV et
  tableau **« Priorisation par risque »** (KEV, puis EPSS, puis sévérité) —
  et compteurs KEV/EPSS/PoC dans le résumé global.
- `scan --format sarif` : propriétés `kev`, `epss`, `epssPercentile`, `poc`,
  `cvssExploitability` sur chaque résultat ; `security-severity` relevé à
  `9.5` pour une CVE KEV (priorisation GitHub Code Scanning).

## [1.4.2] - 2026-09-07

### Added
- Backend OCI syft : émission des **paquets source**. OSV.dev indexe les avis
  Debian/Ubuntu par paquet *source* (`zlib`, `perl`), pas par binaire
  (`zlib1g`, `perl-base`) ; syft ne liste que le binaire (avec un qualifiant
  `upstream=`), qu'OSV-Scanner ne sait pas rattacher à un avis. Le backend
  ajoute désormais un composant par paquet source distinct (`metadata.source`
  / `sourceVersion` de syft), comme le fait cdxgen. Le qualifiant `upstream=`
  est retiré du binaire correspondant pour que Grype ne compte pas la même
  CVE deux fois. Vérifié sur `haproxy:3.4.4` : OSV-Scanner passe de 19 à 58
  CVE Debian (parité avec le SBOM cdxgen), Grype garde exactement le même
  ensemble de CVE uniques (le total brut se dégonfle de 163 à 80, il
  sur-comptait la même CVE sur chaque binaire d'un même source), et la
  section « Notes par CVE » du rapport passe de 4 à 40 entrées.
- `sbom-generator scan -f markdown|asciidoc|pdf` : section **« Notes par CVE »**
  sous la matrice inter-scanners. Pour chaque CVE où Grype ne voit aucun
  correctif pour la distribution installée (`won't fix` / `not fixed`, repris
  du statut `<no-dsa>` du Debian Security Tracker) alors qu'OSV-Scanner ou
  Trivy annoncent une version corrigée, une note précise que cette version est
  en général le correctif des branches *unstable* / *testing* — pas une mise à
  jour disponible pour la release stable. Lève une confusion fréquente : les
  deux scanners ont raison, ils ne parlent pas de la même chose. Les runners
  de scan capturent pour cela `fix.state` / versions corrigées de Grype, les
  événements `fixed` d'OSV et le `FixedVersion` de Trivy.

## [1.4.1] - 2026-09-07

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
- `sbom-generator scan -f markdown|asciidoc|pdf` liste désormais sur stdout,
  une ligne par CVE unique, chaque vulnérabilité **Critical (rouge)** et
  **High (orange)** — paquet concerné + scanners qui l'ont vue + décompte.
  `--color auto` par défaut (couleur si terminal et `NO_COLOR` non défini),
  `--color always` (force, ex. derrière le pipe de `build-dist.sh`),
  `--color never`. `build-dist.sh` affiche ces alertes pendant l'audit du
  build.
- Licences des paquets Dart/Flutter : `pubspec.lock` n'en contient aucune ; le
  CLI lit désormais le fichier `LICENSE` de chaque paquet depuis le cache pub
  (`$PUB_CACHE` / `~/.pub-cache`, auto-détecté ; `--pub-cache <dir>` pour
  forcer, `--pub-cache ""` pour désactiver) et depuis `--flutter-root` pour les
  paquets `source: sdk`. En pratique la licence passe de « quasi aucune » à
  « quasi toutes » (sur la GUI : 63/63 composants, score sbomqs 7.7 → 8.7).
  `identifyArchiveLicense()` reconnaît en plus le texte BSD-3-Clause canonique
  sans le mot « BSD » (cas de presque tous les paquets pub).
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
- Backend OCI syft (Debian) : le qualifiant `distro` des PURL système et la
  version du composant `operating-system` sont ramenés du *point release*
  (`debian-13.6`, tel que syft le lit dans `/etc/debian_version`) au majeur
  (`debian-13`, conforme à `VERSION_ID` d'`/etc/os-release`), et `distro_name`
  (nom de code, ex. `trixie`) est ajouté. OSV-Scanner en mode « scan de SBOM »
  ne rattachait pas `debian-13.6` à l'écosystème `Debian:13` et remontait
  *silencieusement* 0 CVE sur ces SBOM : Grype restait alors seul, avec toutes
  ses correspondances en `wont-fix` / `not-fixed` (statut du Debian Security
  Tracker, sans version corrigée), donnant une image faussement rassurante.
  Distributions non Debian (alpine `3.20.3`, rhel `9.6`…) inchangées : le
  mineur y porte une information. Vérifié sur `haproxy:3.4.4`.

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
