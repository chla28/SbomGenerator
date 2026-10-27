// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Christophe Lafaille

/// Traductions anglaises : la clé est le texte français passé à `tr()`.
library;

const Map<String, String> catalogEn = {
  'Analysés : {uniquePackages}/{targeted} paquet(s).{failedNote}{dupeNote}':
      'Analysed: {uniquePackages}/{targeted} package(s).{failedNote}{dupeNote}',
  'Fichier d\'entrée contenant une référence de paquet par ligne, un\nfichier archive/paquet unique, ou un dossier à parcourir\nrécursivement. Chaque ligne (ou fichier découvert) peut être :\n  • un nom de paquet RPM, un NEVRA ou un chemin vers un .rpm\n  • un chemin vers un paquet Debian .deb\n  • un chemin vers une wheel Python .whl\n  • un chemin vers un fichier requirements.txt\n  • un chemin vers une archive .tar / .tar.gz / .tgz / .zip\n  • un chemin vers un .jar (coordonnées Maven via\n    META-INF/maven/*/*/pom.properties, ou convention de nom)\n  • un chemin vers un fichier go.sum ou go.mod\n  • un chemin vers un package-lock.json ou un yarn.lock\n  • un chemin vers un fichier pom.xml\n  • un chemin vers un pubspec.lock ou un pubspec.yaml\n  • un chemin vers un Cargo.lock, un pnpm-lock.yaml, un composer.lock\n    ou un Gemfile.lock\n  • un chemin vers un uv.lock, un poetry.lock ou un pdm.lock\n  • un chemin vers un Package.resolved (Swift)\n  • un chemin vers un packages.lock.json, un *.deps.json ou un projet\n    .NET (*.csproj, *.fsproj, *.vbproj)\nSi --input est un dossier, tous les types de fichiers ci-dessus\ny sont recherchés récursivement (unzip requis pour les .jar).\nFacultatif si --image est fourni.':
      'Input file containing one package reference per line, a single\narchive/package file, or a directory to scan recursively.\nEach line (or discovered file) may be:\n  • an RPM package name, NEVRA, or path to a .rpm file\n  • a path to a Debian .deb file\n  • a path to a Python .whl file\n  • a path to a requirements.txt file\n  • a path to a .tar / .tar.gz / .tgz / .zip archive\n  • a path to a .jar file (Maven coordinates via\n    META-INF/maven/*/*/pom.properties, or filename convention)\n  • a path to a go.sum or go.mod file\n  • a path to a package-lock.json or yarn.lock file\n  • a path to a pom.xml file\n  • a path to a pubspec.lock or pubspec.yaml file\n  • a path to a Cargo.lock, pnpm-lock.yaml, composer.lock\n    or Gemfile.lock file\n  • a path to a uv.lock, poetry.lock or pdm.lock file\n  • a path to a Package.resolved file (Swift)\n  • a path to a packages.lock.json, a *.deps.json or a .NET project\n    (*.csproj, *.fsproj, *.vbproj)\nIf --input is a directory, it is scanned recursively for all of\nthe file types above (requires unzip for .jar).\nOptional when --image is provided.',
  'Image de conteneur OCI à analyser.\nFormats acceptés :\n  • Registre  : nginx:latest  ubuntu@sha256:…\n  • Archive   : /chemin/image.tar  (docker save)\n  • OCI layout: /chemin/vers/oci_dir/  (index.json présent)\nÀ combiner avec --oci-tool pour choisir le backend.\nUn chemin de fichier local (binaire) fonctionne aussi via le\nbackend syft — voir --binary, plus explicite pour ce cas.':
      'OCI container image to analyse.\nAccepted formats:\n  • Registry  : nginx:latest  ubuntu@sha256:…\n  • Archive   : /path/image.tar  (docker save)\n  • OCI layout: /path/to/oci_dir/  (index.json present)\nCombine with --oci-tool to choose the backend.\nA local file path (binary) also works through the syft\nbackend — see --binary, more explicit for that case.',
  'Binaire local à analyser directement (ex. exécutable Go lié\nstatiquement) — alias explicite pour --image <fichier>.\nForce --oci-tool syft : seul backend qui sait exploiter les\nmétadonnées embarquées dans un binaire autonome (buildinfo Go\nvia `go-module-binary-cataloger`, classifieur générique pour\nquelques bibliothèques connues — OpenSSL, zlib, sqlite…).\nNe récupère PAS les dépendances de bibliothèques liées\nstatiquement sans métadonnée embarquée (C/C++ « fait maison »,\nRust sans cargo-auditable).':
      'Local binary to analyse directly (e.g. a statically linked Go\nexecutable) — explicit alias for --image <file>.\nForces --oci-tool syft: the only backend able to use the\nmetadata embedded in a standalone binary (Go buildinfo via\n`go-module-binary-cataloger`, generic classifier for a few\nwell-known libraries — OpenSSL, zlib, sqlite…).\nDoes NOT recover the dependencies of statically linked\nlibraries lacking embedded metadata (home-grown C/C++,\nRust without cargo-auditable).',
  'Backend d\'analyse OCI (utilisé avec --image).\n  syft    Anchore Syft (défaut) — tous types de paquets\n  trivy   Aqua Trivy — tous types de paquets\n  skopeo  Skopeo + extraction manuelle (dpkg/rpm/apk)\n  cdxgen  OWASP cdxgen — tous types de paquets':
      'OCI analysis backend (used with --image).\n  syft    Anchore Syft (default) — all package types\n  trivy   Aqua Trivy — all package types\n  skopeo  Skopeo + manual extraction (dpkg/rpm/apk)\n  cdxgen  OWASP cdxgen — all package types',
  'Avec --image : génère en plus un SBOM par couche de l\'image\n(delta de la couche : composants ajoutés/modifiés, supprimés\nlistés à part), dans chaque format demandé, à côté de -o :\n<base>.layer-NN-<digest12>.<ext>. Le SBOM global indique la\ncouche d\'origine de chaque composant.':
      'With --image: also generates one SBOM per image layer (layer\ndelta: added/modified components, removed ones listed\nseparately), in each requested format, next to -o:\n<base>.layer-NN-<digest12>.<ext>. The global SBOM states the\noriginating layer of each component.',
  'Méthode de calcul de --per-layer :\n  metadata  couche d\'origine indiquée par le backend (défaut ;\n            syft et trivy uniquement) — rapide, ajouts seulement\n  rootfs    couches appliquées une à une et rootfs réanalysé\n            après chacune — ajouts, modifications, suppressions\n            (défaut forcé pour skopeo et cdxgen)':
      'Computation method for --per-layer:\n  metadata  originating layer reported by the backend (default;\n            syft and trivy only) — fast, additions only\n  rootfs    layers applied one by one and the rootfs re-analysed\n            after each — additions, changes, removals\n            (forced default for skopeo and cdxgen)',
  'Profondeur de descente dans les objets imbriqués de --input :\n  0     l\'objet seul (défaut)\n  N     N niveaux (1 = jars/paquets/archives contenus dans un\n        rpm, deb, tar, zip, jar/war/ear, wheel ; 2 = ce que\n        contiennent ces derniers…)\n  all   sans limite (plafonné à {maxNestedDepth} niveaux)\nLes composants trouvés sont ajoutés au SBOM de l\'objet\n(propriétés location/depth, arêtes de dépendance parent → enfant)\net un SBOM par objet imbriqué est écrit à côté de -o\n(<base>.nested-NN-<objet>.<ext>, voir --no-nested-files).\nLes manifestes rencontrés (package-lock.json, go.sum, pom.xml…)\nsont analysés. Extraction bornée (taille, nombre de fichiers).':
      'Depth of descent into the nested objects of --input:\n  0     the object alone (default)\n  N     N levels (1 = jars/packages/archives contained in an\n        rpm, deb, tar, zip, jar/war/ear, wheel; 2 = what those\n        contain…)\n  all   unlimited (capped at {maxNestedDepth} levels)\nComponents found are added to the object\'s SBOM\n(location/depth properties, parent → child dependency edges)\nand one SBOM per nested object is written next to -o\n(<base>.nested-NN-<object>.<ext>, see --no-nested-files).\nManifests encountered (package-lock.json, go.sum, pom.xml…)\nare analysed. Extraction is bounded (size, number of files).',
  'Avec --depth : écrire un SBOM par objet imbriqué en plus du SBOM\nfusionné. --no-nested-files : fusionné seulement.':
      'With --depth: write one SBOM per nested object in addition to the\nmerged SBOM. --no-nested-files: merged one only.',
  'Chemin du fichier de sortie.\nFormat unique : utilisé tel quel.\nPlusieurs formats (-f a,b) : utilisé comme base ; les extensions\npropres à chaque format sont ajoutées (.cdx.json, .spdx.json,\n.spdx3.jsonld, …).':
      'Output file path.\nSingle format: used as-is.\nMultiple formats (-f a,b): used as a base path; format-specific\nextensions are appended (.cdx.json, .spdx.json, .spdx3.jsonld, …).',
  'Format(s) de sortie, séparés par des virgules.\n  cyclonedx  CycloneDX 1.6 ou 1.7 JSON (défaut : 1.6, voir --cyclonedx-version)\n  spdx       SPDX 2.3 JSON\n  spdx3      SPDX 3.0 JSON-LD\n  json       JSON lisible personnalisé\n  markdown   Tableau Markdown des licences\n  asciidoc   Tableau AsciiDoc des licences\n  html       Rapport HTML interactif (tableau filtrable)\n  csv        Fichier CSV (une ligne par paquet)\nExemple : -f cyclonedx,spdx,csv':
      'Output format(s), comma-separated.\n  cyclonedx  CycloneDX 1.6 or 1.7 JSON (default: 1.6, see --cyclonedx-version)\n  spdx       SPDX 2.3 JSON\n  spdx3      SPDX 3.0 JSON-LD\n  json       Custom human-friendly JSON\n  markdown   Markdown licence table\n  asciidoc   AsciiDoc licence table\n  html       Interactive HTML report (filterable table)\n  csv        CSV file (one row per package)\nExample: -f cyclonedx,spdx,csv',
  'Nom du document SBOM / du composant racine.':
      'Name for the SBOM document / root component.',
  'Fournisseur par défaut des composants dont la source ne porte\naucune information d\'éditeur (lockfiles npm/yarn/Go/pip/pub,\nrequirements.txt…). N\'écrase jamais un fournisseur déjà détecté\n(RPM %{VENDOR}, Maintainer Debian, groupId Maven…).\nChamp obligatoire de BSI TR-03183-2 / éléments minimaux NTIA.':
      'Default supplier for components whose source carries no vendor\ninformation (npm/yarn/Go/pip/pub lockfiles, requirements.txt…).\nNever overrides a supplier that was already detected\n(RPM %{VENDOR}, Debian Maintainer, Maven groupId…).\nMandatory field of BSI TR-03183-2 / NTIA minimum elements.',
  'Dossier où chercher récursivement des fichiers .rpm.\nSert à résoudre les noms de paquet nus (sans chemin ni extension)\nvers des .rpm locaux au lieu d\'interroger la base installée.':
      'Directory to search recursively for .rpm files.\nUsed to resolve bare package names (no path, no extension)\nto local .rpm files instead of querying the installed database.',
  'Affiche le détail de la progression.': 'Print progress details.',
  'Format de la sortie standard.\n  text  texte lisible, barre de progression (défaut)\n  json  un événement JSON par ligne (NDJSON) :\n        {"event":"output","path":…,"kb":…},\n        {"event":"progress","current":…,"total":…,"label":…},\n        {"event":"log","message":…}. Les erreurs restent sur stderr.':
      'Standard output format.\n  text  human-readable text, progress bar (default)\n  json  one JSON event per line (NDJSON):\n        {"event":"output","path":…,"kb":…},\n        {"event":"progress","current":…,"total":…,"label":…},\n        {"event":"log","message":…}. Errors stay on stderr.',
  'Nombre maximal de paquets traités en parallèle.\n1 = séquentiel. 0 = illimité.':
      'Maximum packages processed concurrently.\n1 = sequential. 0 = unlimited.',
  'Chemin d\'un fichier de substitution de licences.\nFormat : un « nom_de_paquet: expression-SPDX » par ligne ; la clé\npeut être un nom, un « groupId:artifactId » Maven ou un PURL sans\nversion (séparateur : « -> », « = » ou le dernier « : »).\nLes lignes commençant par # sont ignorées.\nRemplace la licence détectée pour les noms de paquet concernés.':
      'Path to a license override file.\nFormat: one "package_name: SPDX-expression" per line; the key may\nbe a name, a Maven "groupId:artifactId" or a version-less PURL\n(separator: "->", "=" or the last ":").\nLines starting with # are ignored.\nOverrides the detected license for matching package names.',
  'Fait échouer la génération si un paquet a cette licence.\nPeut être répété. Supporte les expressions SPDX partielles.\nExemple : --deny-license GPL-3.0 --deny-license AGPL-3.0':
      'Fails the generation if a package has this license.\nMay be repeated. Supports partial SPDX expressions.\nExample: --deny-license GPL-3.0 --deny-license AGPL-3.0',
  'Version réelle d\'un SDK Dart/Flutter, pour les paquets\n`source: sdk` d\'un pubspec.lock/pubspec.yaml (que le lockfile\nnote toujours 0.0.0). Format <sdk>=<version>, répétable.\nExemple : --sdk-version flutter=3.47.2 --sdk-version dart=3.9.0':
      'Actual version of a Dart/Flutter SDK, for the `source: sdk`\npackages of a pubspec.lock/pubspec.yaml (which the lockfile\nalways records as 0.0.0). Format <sdk>=<version>, repeatable.\nExample: --sdk-version flutter=3.47.2 --sdk-version dart=3.9.0',
  'Répertoire du cache pub (contient hosted/<hôte>/<nom>-<version>/).\nSert à lire le fichier LICENSE de chaque paquet d\'un pubspec.lock\n(le lockfile ne contient aucune licence). Par défaut : \$PUB_CACHE,\nsinon ~/.pub-cache s\'il existe. Passer "" pour désactiver.':
      'Pub cache directory (contains hosted/<host>/<name>-<version>/).\nUsed to read the LICENSE file of each package of a pubspec.lock\n(the lockfile holds no license). Default: \$PUB_CACHE,\notherwise ~/.pub-cache if it exists. Pass "" to disable.',
  'Racine du SDK Flutter, pour lire le LICENSE des paquets\n`source: sdk` (flutter, sky_engine…). Par défaut : \$FLUTTER_ROOT.':
      'Flutter SDK root, to read the LICENSE of `source: sdk`\npackages (flutter, sky_engine…). Default: \$FLUTTER_ROOT.',
  'Version de la spécification CycloneDX à générer.\n  1.6  (défaut, la plus répandue chez les consommateurs actuels)\n  1.7  Ajoute citations/patentAssertions/distributionConstraints quand --tlp ou --patent-map sont fournis.':
      'CycloneDX specification version to generate.\n  1.6  (default, the most widespread among current consumers)\n  1.7  Adds citations/patentAssertions/distributionConstraints when --tlp or --patent-map are provided.',
  'Classification TLP (Traffic Light Protocol) du BOM.\nNécessite --cyclonedx-version 1.7.\nValeurs : {_validTlpClassifications}':
      'TLP (Traffic Light Protocol) classification of the BOM.\nRequires --cyclonedx-version 1.7.\nValues: {_validTlpClassifications}',
  'Chemin vers un fichier de déclarations de brevets.\nNécessite --cyclonedx-version 1.7.\nFormat : une ligne "nom_de_paquet: numéro|juridiction|statut|type"\nExemple : openssl: US1234567|US|granted|license':
      'Path to a patent declarations file.\nRequires --cyclonedx-version 1.7.\nFormat: one line "package_name: number|jurisdiction|status|type"\nExample: openssl: US1234567|US|granted|license',
  'Score sbomqs minimum (0-10). Échoue si le score est inférieur.\nRequiert que sbomqs soit installé.':
      'Minimum sbomqs score (0-10). Fails if the score is lower.\nRequires sbomqs to be installed.',
  'Signe le SBOM généré avec cosign (requiert cosign installé).\nLa clé est lue depuis les variables d\'environnement cosign standard.':
      'Signs the generated SBOM with cosign (requires cosign installed).\nThe key is read from the standard cosign environment variables.',
  'Langue des messages (défaut : SBOM_LANG, puis LC_ALL/LANG, sinon fr).':
      'Message language (default: SBOM_LANG, then LC_ALL/LANG, else fr).',
  'Affiche la version et quitte.': 'Print version and exit.',
  'Affiche cette aide.': 'Show this help message.',
  'Au moins une source est requise : --input, --image ou --binary.':
      'At least one source is required: --input, --image or --binary.',
  '--image et --binary sont exclusifs (le second est un alias explicite du premier pour un fichier local).':
      '--image and --binary are mutually exclusive (the latter is an explicit alias of the former for a local file).',
  '--binary : fichier introuvable : {binaryPath}':
      '--binary: file not found: {binaryPath}',
  '--binary ne fonctionne qu\'avec --oci-tool syft (seul backend capable d\'analyser un binaire autonome).':
      '--binary only works with --oci-tool syft (the only backend able to analyse a standalone binary).',
  '--concurrency doit être ≥ 0.': '--concurrency must be ≥ 0.',
  '--format ne doit pas être vide.': '--format must not be empty.',
  'Format inconnu "{f}". Valides : {_validFormats}':
      'Unknown format "{f}". Valid: {_validFormats}',
  'Outil OCI inconnu "{ociTool}". Valides : {_validOciTools}':
      'Unknown OCI tool "{ociTool}". Valid: {_validOciTools}',
  '--layer-mode nécessite --per-layer.': '--layer-mode requires --per-layer.',
  '--per-layer nécessite une image de conteneur (--image) : un binaire autonome n\'a pas de couches.':
      '--per-layer requires a container image (--image): a standalone binary has no layers.',
  '--per-layer : mode rootfs (seul mode possible avec {ociTool}).':
      '--per-layer: rootfs mode (the only possible mode with {ociTool}).',
  '--layer-mode rootfs sur une image de registre nécessite skopeo (copie locale des couches).':
      '--layer-mode rootfs on a registry image requires skopeo (local copy of the layers).',
  '--depth attend un entier ≥ 0 ou "all" (reçu "{depth}").':
      '--depth expects an integer ≥ 0 or "all" (got "{depth}").',
  '--depth s\'applique aux objets de --input (rpm, deb, tar, zip, jar…) ; pour une image, voir --per-layer.':
      '--depth applies to --input objects (rpm, deb, tar, zip, jar…); for an image, see --per-layer.',
  '--sdk-version attend <sdk>=<version> (reçu "{entry}").':
      '--sdk-version expects <sdk>=<version> (got "{entry}").',
  'Cache pub pour les licences : {pubCacheDir}':
      'Pub cache for licenses: {pubCacheDir}',
  'Version du SDK Flutter détectée pour {ref} : {d} ; pour une autre version : --sdk-version flutter=<version>.':
      'Flutter SDK version detected for {ref}: {d}; for another version: --sdk-version flutter=<version>.',
  'Substitutions de licence : {licenseOverrides} entrée(s) chargée(s).':
      'License overrides: {licenseOverrides} entr(y/ies) loaded.',
  '--tlp et --patent-map nécessitent --cyclonedx-version 1.7.':
      '--tlp and --patent-map require --cyclonedx-version 1.7.',
  'Entrée introuvable : {inputPath}': 'Input not found: {inputPath}',
  '{found} fichier(s) de paquet trouvé(s) dans {inputPath}.':
      '{found} package file(s) found in {inputPath}.',
  'Aucun paquet reconnu dans le dossier {inputPath}.':
      'No recognised package in directory {inputPath}.',
  '{inputPath} ne semble pas être un fichier texte lisible. Si c\'est une archive (.zip/.tar/.tar.gz/.tgz/.whl/.deb/.rpm/.jar), passez-la directement via --input, sinon --input doit être un fichier listant une référence de paquet par ligne, ou un dossier à scanner.':
      '{inputPath} does not look like a readable text file. If it is an archive (.zip/.tar/.tar.gz/.tgz/.whl/.deb/.rpm/.jar), pass it directly via --input; otherwise --input must be a file listing one package reference per line, or a directory to scan.',
  'Aucun paquet trouvé dans {inputPath} (fichier vide ou lignes toutes commentées).':
      'No packages found in {inputPath} (empty file or all lines are comments).',
  'Dossier RPM introuvable : {rpmDir}': 'RPM directory not found: {rpmDir}',
  '{rpmExactIndex} fichier(s) RPM trouvé(s) dans {rpmDir}.':
      'Found {rpmExactIndex} RPM file(s) in {rpmDir}.',
  'version du SDK Flutter inconnue : les scanners signaleront TOUTES les CVE du SDK, quelle que soit leur plage de versions. Fournir --sdk-version flutter=<version> (ou installer Flutter / définir FLUTTER_ROOT pour la détection automatique).':
      'Flutter SDK version unknown: scanners will report ALL SDK CVEs whatever their affected version range. Provide --sdk-version flutter=<version> (or install Flutter / set FLUTTER_ROOT for automatic detection).',
  '{ociTool} introuvable ou non fonctionnel — requis pour {image}.':
      '{ociTool} not found or not working — required for {image}.',
  'Analyse du binaire via {ociTool} : {imageRef}…':
      'Analysing binary via {ociTool}: {imageRef}…',
  'registre': 'registry',
  'archive tar': 'tar archive',
  'binaire': 'binary',
  'Analyse de l\'image OCI ({refTypeLabel}) via {ociTool} : {imageRef}…':
      'Analysing OCI image ({refTypeLabel}) via {ociTool}: {imageRef}…',
  '{ociPackages} paquet(s) trouvé(s) dans l\'image.':
      '{ociPackages} package(s) found in the image.',
  'OS de base détecté : {id} {version}': 'Base OS detected: {id} {version}',
  'Échec de l\'analyse OCI : {e}': 'OCI analysis failed: {e}',
  'Analyse par couche (mode {layerMode}) via {ociTool}…':
      'Per-layer analysis ({layerMode} mode) via {ociTool}…',
  '⚠  {unattributed} paquet(s) sans couche d\'origine connue — absents des SBOM de couche.':
      '⚠  {unattributed} package(s) with no known originating layer — absent from the layer SBOMs.',
  '{layers} couche(s) analysée(s).': '{layers} layer(s) analysed.',
  'Échec de l\'analyse par couche : {e}': 'Per-layer analysis failed: {e}',
  'binaire rpm introuvable ou non fonctionnel.':
      'rpm binary not found or not functional.',
  'python3 introuvable — requis pour lire les archives .whl, tar et zip.':
      'python3 not found — required to read .whl, tar, and zip archives.',
  'dpkg-deb introuvable — requis pour lire les fichiers .deb.':
      'dpkg-deb not found — required to read .deb files.',
  'unzip introuvable — requis pour lire les fichiers .jar.':
      'unzip not found — required to read .jar files.',
  'illimité': 'unlimited',
  'plusieurs fichiers RPM correspondent à "{ref}" ; utilisation de {last}':
      'multiple RPM files match "{ref}"; using {last}',
  '--depth : aucun objet de --input dans lequel descendre (rpm, deb, tar, zip, jar, wheel).':
      '--depth: no --input object to descend into (rpm, deb, tar, zip, jar, wheel).',
  'Descente dans {roots} objet(s) (profondeur {nestedDepth})…':
      'Descending into {roots} object(s) (depth {nestedDepth})…',
  '{nestedCount} composant(s) trouvé(s) dans {nestedObjects} objet(s) imbriqué(s).':
      '{nestedCount} component(s) found in {nestedObjects} nested object(s).',
  'Substitutions de licence appliquées à {n} paquet(s).':
      'License overrides applied to {n} package(s).',
  'Fournisseur par défaut "{supplierFallback}" appliqué à {before} paquet(s) sans fournisseur détecté.':
      'Supplier fallback "{supplierFallback}" applied to {before} package(s) without a detected supplier.',
  '  ({failed} échec(s))': '  ({failed} failure(s))',
  '  ({dupes} doublon(s) supprimé(s))': '  ({dupes} duplicate(s) removed)',
  '⚠  {failedRefs} paquet(s) ignoré(s) :':
      '⚠  {failedRefs} package(s) skipped:',
  'Aucun paquet n\'a pu être analysé. Abandon.':
      'No packages could be parsed. Aborting.',
  'Résolution des dépendances…': 'Resolving dependencies…',
  '{relCount} relation(s) de dépendance trouvée(s) dans la liste.':
      'Found {relCount} intra-list dependency relationship(s).',
  '  {srcName} → {dependsOn} dépendance(s)': '  {srcName} → {dependsOn} dep(s)',
  'Génération de {label} ({fmt})…': 'Generating {label} ({fmt})…',
  'Échec d\'écriture de {label} ({fmt}) : {e}':
      'Failed to write {label} ({fmt}): {e}',
  'SBOM couche {index}/{total}': 'SBOM layer {index}/{total}',
  'SBOM objet imbriqué {i}/{nestedJobs}': 'SBOM nested object {i}/{nestedJobs}',
  '\nPolitique licence : {violations} violation(s) :':
      '\nLicense policy: {violations} violation(s):',
  'Politiques licences : OK': 'License policies: OK',
  '--min-quality-score : valeur invalide "{minQualityScore}"':
      '--min-quality-score: invalid value "{minQualityScore}"',
  '\nPolitique qualité : score={score} < seuil={threshold} → ÉCHEC':
      '\nQuality policy: score={score} < threshold={threshold} → FAIL',
  'Politique qualité : score={score} >= seuil={threshold} → OK':
      'Quality policy: score={score} >= threshold={threshold} → OK',
  '\n{policyFailures} politique(s) violée(s) — code retour 2':
      '\n{policyFailures} policy violation(s) — exit code 2',
  'Fichier de sortie (JSON). Défaut : affichage console.':
      'Output file (JSON). Default: console output.',
  'Sortie au format JSON structuré.': 'Structured JSON output.',
  'Désactive la coloration ANSI.': 'Disable ANSI colouring.',
  'Aide.': 'Help.',
  'diff: deux fichiers SBOM requis.': 'diff: two SBOM files are required.',
  'Diff écrit → {outPath}': 'Diff written → {outPath}',
  'sbom_generator diff – Compare deux fichiers SBOM et affiche les changements.\n\nUsage:\n  sbom_generator diff <avant.cdx.json> <après.cdx.json> [options]\n\n{usage}\n\nCodes de retour:\n  0  Aucun changement\n  1  Des changements ont été détectés\n':
      'sbom_generator diff – Compares two SBOM files and shows the changes.\n\nUsage:\n  sbom_generator diff <before.cdx.json> <after.cdx.json> [options]\n\n{usage}\n\nExit codes:\n  0  No change\n  1  Changes were detected\n',
  'Fichier SBOM fusionné de sortie (même format que le premier fichier d\'entrée : .cdx.json ou .spdx.json).':
      'Output merged SBOM file (same format as the first input file: .cdx.json or .spdx.json).',
  'Nom du document SBOM fusionné.': 'Name of the merged SBOM document.',
  'merge: au moins deux fichiers SBOM requis.':
      'merge: at least two SBOM files are required.',
  'Fusion de {files} SBOMs → {total} composant(s) → {outPath}':
      'Merged {files} SBOMs → {total} component(s) → {outPath}',
  'sbom_generator merge – Fusionne plusieurs fichiers SBOM en un seul.\n\nUsage:\n  sbom_generator merge <a.cdx.json> <b.cdx.json> [...] -o merged.cdx.json\n\n{usage}\n':
      'sbom_generator merge – Merges several SBOM files into one.\n\nUsage:\n  sbom_generator merge <a.cdx.json> <b.cdx.json> [...] -o merged.cdx.json\n\n{usage}\n',
  'sign: cosign introuvable — signature ignorée.':
      'sign: cosign not found — signature skipped.',
  'cosign : signature de {sbomPath}…': 'cosign: signing {sbomPath}…',
  'cosign: échec (code {exitCode}) : {stderr}':
      'cosign: failed (code {exitCode}): {stderr}',
  'Fichier de correspondance de licences introuvable : {path}':
      'License map file not found: {path}',
  'Fichier de brevets introuvable : {path}':
      'Patent map file not found: {path}',
  '--patent-map : ligne invalide (attendu "name: number|jurisdiction|status|type") : "{trimmed}"':
      '--patent-map: invalid line (expected "name: number|jurisdiction|status|type"): "{trimmed}"',
  'Chemin vers le fichier SBOM à analyser (.cdx.json, .spdx.json…).\nExclusif de --image.':
      'Path to the SBOM file to analyse (.cdx.json, .spdx.json…).\nMutually exclusive with --image.',
  'Image de conteneur à analyser (registre, archive tar, OCI\nlayout) : son SBOM CycloneDX est d\'abord généré (via\n--oci-tool) dans un répertoire temporaire, puis scanné.\nExclusif de --sbom.':
      'Container image to analyse (registry, tar archive, OCI\nlayout): its CycloneDX SBOM is first generated (via\n--oci-tool) in a temporary directory, then scanned.\nMutually exclusive with --sbom.',
  'Paquet ou archive local à analyser directement (rpm, deb,\ntar/tgz, zip, jar/war/ear, wheel) : son SBOM CycloneDX est\nd\'abord généré (voir --depth) dans un répertoire temporaire,\npuis scanné. Exclusif de --sbom et --image.':
      'Local package or archive to analyse directly (rpm, deb,\ntar/tgz, zip, jar/war/ear, wheel): its CycloneDX SBOM is\nfirst generated (see --depth) in a temporary directory,\nthen scanned. Mutually exclusive with --sbom and --image.',
  'Avec --package : profondeur de descente dans les objets\nimbriqués (0 = l\'objet seul, N niveaux, all = sans limite),\ncomme --depth de la génération. Chaque CVE est rattachée à\nl\'objet qui contient le paquet vulnérable (colonne OBJET).':
      'With --package: depth of descent into nested objects\n(0 = the object alone, N levels, all = unlimited), like the\ngeneration --depth. Each CVE is attached to the object that\ncontains the vulnerable package (OBJECT column).',
  'Backend de génération du SBOM pour --image.':
      'SBOM generation backend for --image.',
  'Vulnérabilités par couche d\'image. Avec --sbom, le SBOM doit\nêtre le SBOM global d\'un jeu produit par --per-layer (SBOM de\ncouche à côté) ; avec --image, le jeu est généré.':
      'Vulnerabilities per image layer. With --sbom, the SBOM must\nbe the global SBOM of a set produced by --per-layer (layer\nSBOMs alongside); with --image, the set is generated.',
  'Méthode de --per-layer :\n  attribute  un scan du SBOM global, chaque CVE rattachée à la\n             couche d\'origine de son paquet (défaut)\n  each       SBOM de chaque couche scanné séparément (CVE\n             introduites puis corrigées plus haut incluses)':
      '--per-layer method:\n  attribute  one scan of the global SBOM, each CVE attached to\n             the originating layer of its package (default)\n  each       each layer SBOM scanned separately (CVEs\n             introduced then fixed higher up included)',
  'Avec --image --per-layer : calcul des couches (voir\n--layer-mode de la génération ; défaut metadata pour\nsyft/trivy, rootfs sinon).':
      'With --image --per-layer: layer computation (see the\ngeneration --layer-mode; default metadata for\nsyft/trivy, rootfs otherwise).',
  'Scanner(s) à utiliser.\n  grype   Anchore Grype\n  osv     Google OSV-Scanner\n  trivy   Aqua Security Trivy\n  all     Les trois scanners':
      'Scanner(s) to use.\n  grype   Anchore Grype\n  osv     Google OSV-Scanner\n  trivy   Aqua Security Trivy\n  all     All three scanners',
  'N\'afficher que les CVE publiées/modifiées après cette date (YYYY-MM-DD)':
      'Only show CVEs published/modified after this date (YYYY-MM-DD)',
  'N\'afficher que les CVE publiées/modifiées avant cette date (YYYY-MM-DD)':
      'Only show CVEs published/modified before this date (YYYY-MM-DD)',
  'Champ de date à utiliser pour le filtre.\n  published   Date de publication (défaut)\n  modified    Date de dernière modification\n  latest      La plus récente des deux':
      'Date field to use for the filter.\n  published   Publication date (default)\n  modified    Last modification date\n  latest      The more recent of the two',
  'Inclure les CVE sans date dans les résultats filtrés':
      'Include undated CVEs in the filtered results',
  'Format de sortie.\n  text      Texte coloré sur stdout (défaut)\n  json      Résultats en JSON (stdout si -o omis) ; sert de\n            référence pour --baseline\n  sarif     SARIF 2.1.0 (intégration GitHub Code Scanning)\n  markdown  Rapport de synthèse inter-scanners (Markdown)\n  asciidoc  Rapport de synthèse inter-scanners (AsciiDoc)\n  pdf       Idem asciidoc + conversion via asciidoctor-pdf':
      'Output format.\n  text      Coloured text on stdout (default)\n  json      Results as JSON (stdout if -o omitted); used as\n            the reference for --baseline\n  sarif     SARIF 2.1.0 (GitHub Code Scanning integration)\n  markdown  Cross-scanner summary report (Markdown)\n  asciidoc  Cross-scanner summary report (AsciiDoc)\n  pdf       Same as asciidoc + conversion via asciidoctor-pdf',
  'Fichier de sortie. Requis pour --format markdown/asciidoc/pdf ;\npour --format sarif/json, écrit sur stdout si omis.':
      'Output file. Required for --format markdown/asciidoc/pdf;\nfor --format sarif/json, written to stdout if omitted.',
  'Coloration ANSI des alertes Critical/High (formats rapport).\n  auto    si stdout est un terminal et NO_COLOR non défini (défaut)\n  always  toujours (utile derrière un pipe : build-dist.sh)\n  never   jamais (préfixes [CRITICAL]/[HIGH])':
      'ANSI colouring of Critical/High alerts (report formats).\n  auto    if stdout is a terminal and NO_COLOR is unset (default)\n  always  always (useful behind a pipe: build-dist.sh)\n  never   never ([CRITICAL]/[HIGH] prefixes)',
  'Enrichir chaque CVE avec les signaux d\'exploitabilité :\n  CISA KEV (exploitée dans la nature), EPSS (probabilité),\n  PoC public, sous-score d\'exploitabilité CVSS.\n  --no-enrich : hors-ligne, uniquement ce que les scanners\n  fournissent déjà + le cache local. Forcé par SBOMGEN_OFFLINE=1.':
      'Enrich each CVE with exploitability signals:\n  CISA KEV (exploited in the wild), EPSS (probability),\n  public PoC, CVSS exploitability sub-score.\n  --no-enrich: offline, only what the scanners already\n  provide + the local cache. Forced by SBOMGEN_OFFLINE=1.',
  'Interroger la source PoC tierce (poc-in-github). --no-poc\ngarde KEV/EPSS et la maturité « E: » du vecteur CVSS.':
      'Query the third-party PoC source (poc-in-github). --no-poc\nkeeps KEV/EPSS and the "E:" maturity of the CVSS vector.',
  'Délai maximal (secondes) par requête d\'enrichissement.':
      'Maximum delay (seconds) per enrichment request.',
  'Ne garder que les CVE présentes au catalogue CISA KEV.':
      'Keep only the CVEs listed in the CISA KEV catalog.',
  'Ne garder que les CVE dont le score EPSS est ≥ cette valeur (0..1, ex. 0.1).':
      'Keep only the CVEs whose EPSS score is ≥ this value (0..1, e.g. 0.1).',
  'Ordre d\'affichage console.\n  severity  pire sévérité d\'abord (défaut)\n  risk      KEV, puis EPSS décroissant, puis sévérité':
      'Console display order.\n  severity  worst severity first (default)\n  risk      KEV, then EPSS descending, then severity',
  'Écrit un document VEX : les CVE restantes en "affected" (avec\nla version corrigée), plus les déclarations "not_affected"\nreprises de --vex.':
      'Writes a VEX document: remaining CVEs as "affected" (with the\nfixed version), plus the "not_affected" statements carried\nover from --vex.',
  'Format de --vex-out.': 'Format of --vex-out.',
  'Auteur inscrit dans --vex-out.': 'Author recorded in --vex-out.',
  'Fichier de CVE ignorées, une règle par ligne :\n  CVE-2024-1234; package=openssl; expires=2026-12-31; reason=…\n(seul l\'identifiant est obligatoire ; une règle expirée\nn\'est plus appliquée et est signalée).':
      'File of ignored CVEs, one rule per line:\n  CVE-2024-1234; package=openssl; expires=2026-12-31; reason=…\n(only the identifier is mandatory; an expired rule is no\nlonger applied and is reported).',
  'Rapport de référence produit par `scan --format json` : les\nCVE déjà présentes (même identifiant, même paquet) sont\nécartées ; seules les NOUVELLES restent.':
      'Baseline report produced by `scan --format json`: CVEs already\npresent (same identifier, same package) are dropped; only\nNEW ones remain.',
  'Code retour 1 seulement si une CVE restante a au moins cette\nsévérité (critical, high, medium, low). Par défaut : toute\nCVE restante fait échouer.':
      'Exit code 1 only if a remaining CVE has at least this severity\n(critical, high, medium, low). Default: any remaining CVE fails.',
  'Rapports (markdown/asciidoc/pdf) : ne garder que les CVE dont la\npire sévérité atteint ce seuil (critical, high, medium), plus\ncelles du catalogue CISA KEV. Défaut : all.':
      'Reports (markdown/asciidoc/pdf): keep only the CVEs whose worst\nseverity reaches this threshold (critical, high, medium), plus\nthose in the CISA KEV catalog. Default: all.',
  'Rapports : section « Tendance » par rapport à un `scan --format\njson` antérieur (ou une session de la GUI).':
      'Reports: "Trend" section against an earlier `scan --format json`\n(or a GUI session).',
  'Réutilise le résultat d\'un scanner déjà obtenu pour le même\ncontenu de SBOM (même composants), la même version du scanner,\ndans la limite de --cache-ttl. Évite de relancer le scanner.':
      'Reuses a scanner result already obtained for the same SBOM\ncontent (same components) and scanner version, within\n--cache-ttl. Avoids rerunning the scanner.',
  'Durée de validité du cache, en heures (la base de\nvulnérabilités évolue).':
      'Cache lifetime in hours (the vulnerability database changes).',
  'Répertoire du cache (défaut : ~/.cache/sbom-generator/scan).':
      'Cache directory (default: ~/.cache/sbom-generator/scan).',
  'Afficher l\'aide de la sous-commande scan': 'Show the scan subcommand help',
  'scan: indiquer --sbom <fichier>, --image <image> ou --package <fichier> (exactement l\'un des trois).':
      'scan: specify --sbom <file>, --image <image> or --package <file> (exactly one of the three).',
  'scan: --depth attend un entier ≥ 0 ou "all" (reçu "{scanDepthRaw}").':
      'scan: --depth expects an integer ≥ 0 or "all" (got "{scanDepthRaw}").',
  'scan: --depth nécessite --package.': 'scan: --depth requires --package.',
  'scan: --per-layer ne s\'applique qu\'aux images (--image / --sbom d\'un jeu par couche).':
      'scan: --per-layer only applies to images (--image / --sbom of a per-layer set).',
  'scan: fichier introuvable : {packageRef}':
      'scan: file not found: {packageRef}',
  'scan: --layer-mode nécessite --image et --per-layer.':
      'scan: --layer-mode requires --image and --per-layer.',
  'scan: --epss-min doit être un nombre entre 0 et 1 (reçu "{rawEpssMin}")':
      'scan: --epss-min must be a number between 0 and 1 (got "{rawEpssMin}")',
  'scan: scanner invalide "{scanner}". Valides : {_validScanners}':
      'scan: invalid scanner "{scanner}". Valid: {_validScanners}',
  'scan: cve-date-field invalide "{dateField}". Valides : {_validDateFields}':
      'scan: invalid cve-date-field "{dateField}". Valid: {_validDateFields}',
  'scan: format invalide "{format}". Valides : {_validScanFormats}':
      'scan: invalid format "{format}". Valid: {_validScanFormats}',
  'scan: fichier SBOM introuvable : {sbomFile}':
      'scan: SBOM file not found: {sbomFile}',
  'scan: format de date invalide pour --cve-after : "{rawAfter}" (attendu YYYY-MM-DD)':
      'scan: invalid date format for --cve-after: "{rawAfter}" (expected YYYY-MM-DD)',
  'scan: format de date invalide pour --cve-before : "{rawBefore}" (attendu YYYY-MM-DD)':
      'scan: invalid date format for --cve-before: "{rawBefore}" (expected YYYY-MM-DD)',
  'scan: --output <fichier> est requis pour --format {format}.':
      'scan: --output <file> is required for --format {format}.',
  'scan: résultat {s} lu dans le cache (--cache).':
      'scan: {s} result read from the cache (--cache).',
  'scan: échec de la génération du SBOM de {packageRef} (code {code}).':
      'scan: SBOM generation failed for {packageRef} (code {code}).',
  'Génération du SBOM de l\'image {imageRef}…':
      'Generating the SBOM of image {imageRef}…',
  'scan: échec de la génération du SBOM de {imageRef} (code {code}).':
      'scan: SBOM generation failed for {imageRef} (code {code}).',
  'scan: {sbomFile} ne porte aucune information de couche — produire le SBOM avec --per-layer (ou utiliser --image).':
      'scan: {sbomFile} carries no layer information — produce the SBOM with --per-layer (or use --image).',
  'par couche': 'per layer',
  '  {unknown} résultat(s) sans couche d\'origine connue (paquet absent du SBOM global).':
      '  {unknown} result(s) with no known originating layer (package absent from the global SBOM).',
  '{vexCount} écartée(s) par VEX': '{vexCount} dropped by VEX',
  '{ignoredCount} ignorée(s) (--ignore)': '{ignoredCount} ignored (--ignore)',
  '{baselineCount} déjà connue(s) (--baseline)':
      '{baselineCount} already known (--baseline)',
  'scan : {note}.': 'scan: {note}.',
  'VEX écrit → {vexOutPath} ({statements} déclaration(s))':
      'VEX written → {vexOutPath} ({statements} statement(s))',
  'inconnue': 'unknown',
  'paquet {packageRef}': 'package {packageRef}',
  'JSON écrit → {outputPath}': 'JSON written → {outputPath}',
  'SARIF écrit → {outputPath}': 'SARIF written → {outputPath}',
  'scan: aucun scanner n\'a produit de résultat — rapport non généré.':
      'scan: no scanner produced any result — report not generated.',
  '{cmd}: fichier VEX introuvable : {path}':
      '{cmd}: VEX file not found: {path}',
  '{cmd}: --vex {path} : JSON illisible ({e})':
      '{cmd}: --vex {path}: unreadable JSON ({e})',
  '{cmd}: fichier --ignore introuvable : {path}':
      '{cmd}: --ignore file not found: {path}',
  '{cmd}: règle ignorée EXPIRÉE (ligne {line}) : {id}{package} — non appliquée.':
      '{cmd}: ignore rule EXPIRED (line {line}): {id}{package} — not applied.',
  '{cmd}: fichier introuvable : {path}': '{cmd}: file not found: {path}',
  '{cmd}: {path} : lecture impossible ({e})': '{cmd}: {path}: unreadable ({e})',
  'CVE par couche': 'CVEs per layer',
  'scan de chaque couche': 'each layer scanned',
  'rattachement au SBOM global': 'attributed from the global SBOM',
  'COUCHE': 'LAYER',
  'INSTRUCTION': 'INSTRUCTION',
  ', dont {kevCount} au catalogue CISA KEV':
      ', of which {kevCount} in the CISA KEV catalog',
  '→ {crit} CVE critique(s), {high} CVE High{kevSuffix}':
      '→ {crit} critical CVE(s), {high} High CVE(s){kevSuffix}',
  'Rapport Markdown écrit → {outputPath}':
      'Markdown report written → {outputPath}',
  'Rapport AsciiDoc écrit → {adocPath}': 'AsciiDoc report written → {adocPath}',
  'Rapport PDF écrit → {outputPath}': 'PDF report written → {outputPath}',
  'scan: asciidoctor-pdf a échoué (code {exitCode}) : {trim}':
      'scan: asciidoctor-pdf failed (code {exitCode}): {trim}',
  'scan: rapport AsciiDoc conservé → {adocPath}':
      'scan: AsciiDoc report kept → {adocPath}',
  'scan: asciidoctor-pdf introuvable — PDF non généré, rapport AsciiDoc conservé → {adocPath}':
      'scan: asciidoctor-pdf not found — PDF not generated, AsciiDoc report kept → {adocPath}',
  'grype: introuvable ({message}). Installez-le ou omettez --scanner grype.':
      'grype: not found ({message}). Install it or omit --scanner grype.',
  'grype: erreur (code {exitCode}) : {stderr}':
      'grype: error (code {exitCode}): {stderr}',
  'grype: impossible de parser le JSON: {e}':
      'grype: unable to parse the JSON: {e}',
  'osv-scanner: introuvable ({message}). Installez-le ou omettez --scanner osv.':
      'osv-scanner: not found ({message}). Install it or omit --scanner osv.',
  'osv-scanner: erreur (code {exitCode}) : {stderr}':
      'osv-scanner: error (code {exitCode}): {stderr}',
  'osv-scanner: impossible de parser le JSON: {e}':
      'osv-scanner: unable to parse the JSON: {e}',
  'trivy: introuvable ({message}). Installez-le ou omettez --scanner trivy.':
      'trivy: not found ({message}). Install it or omit --scanner trivy.',
  'trivy: erreur (code {exitCode}) : {stderr}':
      'trivy: error (code {exitCode}): {stderr}',
  'trivy: impossible de parser le JSON: {e}':
      'trivy: unable to parse the JSON: {e}',
  'scan: enrichissement CVE indisponible ({e})':
      'scan: CVE enrichment unavailable ({e})',
  '  Filtre : champ={field}': '  Filter: field={field}',
  '  après={after}': '  after={after}',
  '  avant={before}': '  before={before}',
  '  {vulns} CVE(s) trouvée(s){filterDesc}':
      '  {vulns} CVE(s) found{filterDesc}',
  'SÉVÉRITÉ': 'SEVERITY',
  'PAQUET': 'PACKAGE',
  'PoC  COUCHE': 'PoC  LAYER',
  '  OBJET': '  OBJECT',
  'sbom_generator scan – Analyser les CVE d\'un fichier SBOM avec filtre par date.\n\nUsage:\n  sbom-generator scan --sbom <fichier.cdx.json> [options]\n  sbom-generator scan --image <image> [--per-layer] [options]\n  sbom-generator scan --package <rpm|deb|tgz|zip|jar…> [--depth N] [options]\n\n{usage}\n\nExemples:\n  # Toutes les CVE grype depuis 2024\n  sbom-generator scan --sbom sbom.cdx.json --cve-after 2024-01-01\n\n  # CVE OSV-Scanner entre deux dates\n  sbom-generator scan --sbom sbom.cdx.json --scanner osv \\\n    --cve-after 2023-06-01 --cve-before 2024-01-01\n\n  # Tous les scanners, champ modification, CVE sans date incluses\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --cve-date-field modified --cve-after 2023-01-01 --include-undated\n\n  # Export SARIF (GitHub Code Scanning) vers un fichier\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --format sarif --output results.sarif\n\n  # Rapport de synthèse PDF (Grype + OSV-Scanner + Trivy)\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --format pdf --output scan-report.pdf\n\n  # Seulement les CVE activement exploitées (CISA KEV), triées par risque\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --only-kev --sort risk\n\n  # Prioriser : CVE avec une probabilité d\'exploitation EPSS ≥ 10 %\n  sbom-generator scan --sbom sbom.cdx.json --epss-min 0.1\n\n  # Hors-ligne : pas de requête réseau (KEV/EPSS/PoC seulement via Grype + cache)\n  sbom-generator scan --sbom sbom.cdx.json --no-enrich\n\n  # CVE par couche d\'une image (SBOM généré à la volée, un scan rattaché)\n  sbom-generator scan --image ./app.tar --per-layer --scanner all\n\n  # Idem, SBOM de chaque couche scanné (couches calculées en mode rootfs),\n  # rapport PDF avec section « Couches de l\'image »\n  sbom-generator scan --image nginx:latest --per-layer --layer-scan each \\\n    --layer-mode rootfs --scanner all -f pdf -o nginx-layers.pdf\n\n  # À partir d\'un jeu déjà produit par sbom-generator --per-layer\n  sbom-generator scan --sbom out/app.cdx.json --per-layer\n\n  # Scanner directement un RPM et les jars qu\'il contient (2 niveaux) ;\n  # chaque CVE indique l\'objet (rpm, jar…) qui contient le paquet vulnérable\n  sbom-generator scan --package app-1.0-1.x86_64.rpm --depth 2 --scanner all\n\n  # Archive : tout ce qu\'elle contient, sans limite de profondeur\n  sbom-generator scan --package release.tar.gz --depth all\n\nEnrichissement : chaque CVE est complétée par CISA KEV (exploitée dans la\nnature), EPSS (probabilité d\'exploitation à 30 jours), un signal PoC public\net le sous-score d\'exploitabilité CVSS. Actif par défaut ; --no-enrich (ou\nSBOMGEN_OFFLINE=1) le désactive, --no-poc ne coupe que la source tierce.\n\nEn --format markdown/asciidoc/pdf, chaque CVE Critical (rouge) et High\n(orange) est aussi listée sur stdout, une ligne par CVE unique\n(dédupliquée entre scanners), avec les marqueurs [KEV] / EPSS / [PoC] —\nutile pendant un build. --color auto par défaut (couleur si stdout est un\nterminal et NO_COLOR non défini) ; --color always force la couleur\nderrière un pipe.\n\nCodes de retour:\n  text / sarif :\n    0  Aucune CVE dans la plage demandée\n    1  Au moins une CVE trouvée (ou erreur de scanner)\n  markdown / asciidoc / pdf :\n    0  Rapport produit (quel que soit le nombre de CVE ; pour pdf, le\n       .adoc est conservé si asciidoctor-pdf est absent)\n    1  Aucun scanner n\'a produit de résultat, ou --output manquant\n':
      'sbom_generator scan – Scan the CVEs of an SBOM file, with date filtering.\n\nUsage:\n  sbom-generator scan --sbom <file.cdx.json> [options]\n  sbom-generator scan --image <image> [--per-layer] [options]\n  sbom-generator scan --package <rpm|deb|tgz|zip|jar…> [--depth N] [options]\n\n{usage}\n\nExamples:\n  # All grype CVEs since 2024\n  sbom-generator scan --sbom sbom.cdx.json --cve-after 2024-01-01\n\n  # OSV-Scanner CVEs between two dates\n  sbom-generator scan --sbom sbom.cdx.json --scanner osv \\\n    --cve-after 2023-06-01 --cve-before 2024-01-01\n\n  # All scanners, modification field, undated CVEs included\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --cve-date-field modified --cve-after 2023-01-01 --include-undated\n\n  # SARIF export (GitHub Code Scanning) to a file\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --format sarif --output results.sarif\n\n  # PDF summary report (Grype + OSV-Scanner + Trivy)\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --format pdf --output scan-report.pdf\n\n  # Only actively exploited CVEs (CISA KEV), sorted by risk\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --only-kev --sort risk\n\n  # Prioritise: CVEs with an EPSS exploitation probability ≥ 10 %\n  sbom-generator scan --sbom sbom.cdx.json --epss-min 0.1\n\n  # Offline: no network request (KEV/EPSS/PoC only via Grype + cache)\n  sbom-generator scan --sbom sbom.cdx.json --no-enrich\n\n  # CVEs per image layer (SBOM generated on the fly, one attributed scan)\n  sbom-generator scan --image ./app.tar --per-layer --scanner all\n\n  # Same, each layer SBOM scanned (layers computed in rootfs mode),\n  # PDF report with an "Image layers" section\n  sbom-generator scan --image nginx:latest --per-layer --layer-scan each \\\n    --layer-mode rootfs --scanner all -f pdf -o nginx-layers.pdf\n\n  # From a set already produced by sbom-generator --per-layer\n  sbom-generator scan --sbom out/app.cdx.json --per-layer\n\n  # Scan an RPM and the jars it contains directly (2 levels);\n  # each CVE names the object (rpm, jar…) containing the vulnerable package\n  sbom-generator scan --package app-1.0-1.x86_64.rpm --depth 2 --scanner all\n\n  # Archive: everything it contains, with no depth limit\n  sbom-generator scan --package release.tar.gz --depth all\n\nEnrichment: each CVE is completed with CISA KEV (exploited in the wild),\nEPSS (30-day exploitation probability), a public PoC signal and the CVSS\nexploitability sub-score. On by default; --no-enrich (or SBOMGEN_OFFLINE=1)\nturns it off, --no-poc only cuts the third-party source.\n\nWith --format markdown/asciidoc/pdf, each Critical (red) and High (orange)\nCVE is also listed on stdout, one line per unique CVE (deduplicated across\nscanners), with [KEV] / EPSS / [PoC] markers — handy during a build.\n--color auto by default (colour if stdout is a terminal and NO_COLOR is\nunset); --color always forces colour behind a pipe.\n\nExit codes:\n  text / sarif:\n    0  No CVE in the requested range\n    1  At least one CVE found (or scanner error)\n  markdown / asciidoc / pdf:\n    0  Report produced (whatever the number of CVEs; for pdf, the\n       .adoc is kept if asciidoctor-pdf is missing)\n    1  No scanner produced any result, or --output missing\n',
  '{id} — sévérité {severity}': '{id} — {severity} severity',
  'Résultats de scan : fichier `scan --format json` ou session de\nla GUI (« Enregistrer la session… »).':
      'Scan results: a `scan --format json` file or a GUI session\n("Save session…").',
  'Fichier du rapport (.pdf, .adoc ou .md selon --format).':
      'Report file (.pdf, .adoc or .md depending on --format).',
  'Format du rapport.': 'Report format.',
  'Ne garder que les CVE dont la pire sévérité atteint ce seuil\n(critical, high, medium), plus celles du catalogue CISA KEV.':
      'Keep only the CVEs whose worst severity reaches this threshold\n(critical, high, medium), plus those in the CISA KEV catalog.',
  'Section « Tendance » par rapport à un autre fichier de résultats.':
      '"Trend" section against another results file.',
  'Ignorer les déclarations VEX embarquées dans le fichier.':
      'Ignore the VEX statements embedded in the file.',
  'sbom_generator report – Rapport de vulnérabilités (synthèse inter-scanners,\nremédiation, tendance, VEX, détail des CVE) à partir de résultats déjà obtenus,\nsans relancer les scanners. C\'est le même rapport que `scan --format pdf` et que\nl\'export du tableau de bord de la GUI.\n\nUsage:\n  sbom-generator report -i resultats.json -o rapport.pdf\n  sbom-generator report -i session.json -s high --compare-with ancien.json -o rapport.pdf\n\n{usage}\n':
      'sbom_generator report – Vulnerability report (cross-scanner summary, remediation,\ntrend, VEX, CVE details) from results already obtained, without rerunning the\nscanners. It is the same report as `scan --format pdf` and the GUI dashboard\nexport.\n\nUsage:\n  sbom-generator report -i results.json -o report.pdf\n  sbom-generator report -i session.json -s high --compare-with old.json -o report.pdf\n\n{usage}\n',
  'Identifiant(s) de vulnérabilité (CVE-…, GHSA-…). Répétable.':
      'Vulnerability identifier(s) (CVE-…, GHSA-…). Repeatable.',
  'Produit(s) concerné(s) : PURL, `nom` ou `nom@version`.\nRépétable ; omis = tous les produits.':
      'Product(s) concerned: PURL, `name` or `name@version`.\nRepeatable; omitted = all products.',
  'État de la vulnérabilité pour ces produits.':
      'Vulnerability status for these products.',
  'Obligatoire pour not_affected (vocabulaire OpenVEX).':
      'Required for not_affected (OpenVEX vocabulary).',
  'Explication libre (pourquoi non affecté).':
      'Free-text explanation (why not affected).',
  'Action recommandée (pour affected).': 'Recommended action (for affected).',
  'Auteur du document.': 'Document author.',
  'Document VEX existant (OpenVEX, CycloneDX ou CSAF) auquel ajouter les\ndéclarations ; le résultat est réécrit dans -o.':
      'Existing VEX document (OpenVEX, CycloneDX or CSAF) to add the\nstatements to; the result is rewritten to -o.',
  'Format du document produit : openvex (défaut), cyclonedx ou csaf\n(CSAF 2.0 VEX), ou celui de --append.':
      'Output document format: openvex (default), cyclonedx or csaf\n(CSAF 2.0 VEX), or that of --append.',
  'Fichier de sortie (stdout si omis).': 'Output file (stdout if omitted).',
  'sbom_generator vex – Crée ou complète un document VEX (OpenVEX / CycloneDX / CSAF).\n\nUsage:\n  sbom-generator vex --cve CVE-2024-1234 --product pkg:npm/foo@1.0.0 \\\n    --status not_affected --justification vulnerable_code_not_in_execute_path \\\n    --impact-statement "Fonction non appelée" -o vex.json\n\n{usage}\n\nLe document produit s\'utilise avec `scan --vex vex.json`.\n':
      'sbom_generator vex – Creates or extends a VEX document (OpenVEX / CycloneDX / CSAF).\n\nUsage:\n  sbom-generator vex --cve CVE-2024-1234 --product pkg:npm/foo@1.0.0 \\\n    --status not_affected --justification vulnerable_code_not_in_execute_path \\\n    --impact-statement "Function never called" -o vex.json\n\n{usage}\n\nThe resulting document is used with `scan --vex vex.json`.\n',
  'vex: au moins un --cve est requis.': 'vex: at least one --cve is required.',
  'vex: not_affected exige --justification (ou --impact-statement).':
      'vex: not_affected requires --justification (or --impact-statement).',
  'vex: fichier introuvable : {appendPath}':
      'vex: file not found: {appendPath}',
  'VEX écrit → {out} ({statements} déclaration(s))':
      'VEX written → {out} ({statements} statement(s))',
  'Fichier SBOM source (CycloneDX JSON ou SPDX JSON/JSON-LD).':
      'Source SBOM file (CycloneDX JSON or SPDX JSON/JSON-LD).',
  'Fichier de sortie. Avec plusieurs formats (-f a,b) : chemin de base.':
      'Output file. With several formats (-f a,b): base path.',
  'Format(s) cible(s), séparés par des virgules.\n  cyclonedx  spdx  spdx3  json  markdown  asciidoc  html  csv':
      'Target format(s), comma-separated.\n  cyclonedx  spdx  spdx3  json  markdown  asciidoc  html  csv',
  'Nom du document SBOM de sortie (remplace celui du fichier source).':
      'Name of the output SBOM document (replaces the source file\'s).',
  'Fournisseur par défaut des composants sans éditeur dans le SBOM\nsource. N\'écrase jamais un fournisseur déjà présent.':
      'Default supplier for components with no vendor in the source\nSBOM. Never overrides an existing supplier.',
  'Version CycloneDX cible quand -f inclut "cyclonedx" (défaut : 1.6).':
      'Target CycloneDX version when -f includes "cyclonedx" (default: 1.6).',
  'convert: format inconnu "{f}". Valides : {_validFormats}':
      'convert: unknown format "{f}". Valid: {_validFormats}',
  'convert: fichier introuvable : {inputPath}':
      'convert: file not found: {inputPath}',
  'convert: impossible de lire le JSON : {e}':
      'convert: unable to read the JSON: {e}',
  'convert: format SBOM non reconnu dans {inputPath}':
      'convert: unrecognised SBOM format in {inputPath}',
  '  Formats supportés : CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD':
      '  Supported formats: CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD',
  'convert: erreur de lecture : {e}': 'convert: read error: {e}',
  'Conversion : {inputPath} ({formatLabel}, {packages} composant(s))':
      'Conversion: {inputPath} ({formatLabel}, {packages} component(s))',
  'convert: échec de l\'écriture ({fmt}) : {e}':
      'convert: write failed ({fmt}): {e}',
  'sbom_generator convert – Convertit un fichier SBOM vers un ou plusieurs formats.\n\nUsage:\n  sbom_generator convert -i source.cdx.json -f spdx -o output.spdx.json\n  sbom_generator convert -i source.spdx.json -f cyclonedx,csv -o output\n\nFormats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\nFormats cible supportés  : cyclonedx, spdx, spdx3, json, markdown, asciidoc, html, csv\n\n{usage}\n':
      'sbom_generator convert – Converts an SBOM file to one or more formats.\n\nUsage:\n  sbom_generator convert -i source.cdx.json -f spdx -o output.spdx.json\n  sbom_generator convert -i source.spdx.json -f cyclonedx,csv -o output\n\nSupported source formats: CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\nSupported target formats: cyclonedx, spdx, spdx3, json, markdown, asciidoc, html, csv\n\n{usage}\n',
  'Fichier de sortie (ex : licences.adoc). Facultatif avec --format json (sortie standard).':
      'Output file (e.g. licences.adoc). Optional with --format json (standard output).',
  'Nom du document (remplace celui du fichier source).':
      'Document name (replaces the source file\'s).',
  'licenses: --output est obligatoire (sauf avec --format json).':
      'licenses: --output is required (except with --format json).',
  'licenses: fichier introuvable : {inputPath}':
      'licenses: file not found: {inputPath}',
  'licenses: impossible de lire le JSON : {e}':
      'licenses: unable to read the JSON: {e}',
  'licenses: format SBOM non reconnu dans {inputPath}':
      'licenses: unrecognised SBOM format in {inputPath}',
  'licenses: erreur de lecture : {e}': 'licenses: read error: {e}',
  'Rapport de licences : {inputPath} ({packages} composant(s))':
      'License report: {inputPath} ({packages} component(s))',
  'licenses: échec de l\'écriture : {e}': 'licenses: write failed: {e}',
  'sbom_generator licenses – Génère un rapport de licences à partir d\'un fichier SBOM\n(AsciiDoc par défaut ; Markdown, HTML, CSV ou JSON avec --format).\n\nLe rapport regroupe les paquets par licence, avec un résumé et des\navertissements pour les licences copyleft (GPL/AGPL/LGPL/MPL/EPL/CDDL/CPL/EUPL)\net les paquets sans licence détectée.\n\nUsage:\n  sbom_generator licenses -i sbom.cdx.json -o licences.adoc\n  sbom_generator licenses -i sbom.spdx.json -o licences.adoc -n "Mon projet"\n  sbom_generator licenses -i sbom.cdx.json -f html -o licences.html\n  sbom_generator licenses -i sbom.cdx.json -f json        # JSON sur stdout\n\nFormats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\n\n{usage}\n':
      'sbom_generator licenses – Generates a license report from an SBOM file\n(AsciiDoc by default; Markdown, HTML, CSV or JSON with --format).\n\nThe report groups packages by license, with a summary and warnings for\ncopyleft licenses (GPL/AGPL/LGPL/MPL/EPL/CDDL/CPL/EUPL) and for packages\nwith no detected license.\n\nUsage:\n  sbom_generator licenses -i sbom.cdx.json -o licences.adoc\n  sbom_generator licenses -i sbom.spdx.json -o licences.adoc -n "My project"\n  sbom_generator licenses -i sbom.cdx.json -f html -o licences.html\n  sbom_generator licenses -i sbom.cdx.json -f json        # JSON on stdout\n\nSupported source formats: CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\n\n{usage}\n',
  'Fichier SBOM à évaluer (CycloneDX JSON ou SPDX JSON).':
      'SBOM file to assess (CycloneDX JSON or SPDX JSON).',
  'Fichier de métadonnées fabricant/produit (clé: valeur par ligne). Défaut : ./cra.yaml s\'il existe.':
      'Manufacturer/product metadata file (key: value per line). Default: ./cra.yaml if it exists.',
  'Nom du fabricant (surcharge --config).':
      'Manufacturer name (overrides --config).',
  'Nom du produit.': 'Product name.',
  'Version du produit.': 'Product version.',
  'Date de fin de support (AAAA-MM-JJ).': 'End-of-support date (YYYY-MM-DD).',
  'Adresse (e-mail ou URL) de signalement des vulnérabilités.':
      'Address (e-mail or URL) for reporting vulnerabilities.',
  'URL de la politique de divulgation coordonnée.':
      'URL of the coordinated vulnerability disclosure policy.',
  'Lancer une analyse de vulnérabilités (grype/osv/trivy) pour évaluer l\'inventaire et les correctifs. --no-scan pour s\'en passer.':
      'Run a vulnerability scan (grype/osv/trivy) to assess the inventory and the fixes. --no-scan to skip it.',
  'Scanner(s) : grype (défaut), osv, trivy, all.':
      'Scanner(s): grype (default), osv, trivy, all.',
  'Fichier de CVE ignorées (voir `scan --help`) : règles\njustifiées et datées, écartées de l\'inventaire.':
      'File of ignored CVEs (see `scan --help`): justified, dated\nrules removed from the inventory.',
  'Enrichir les CVE (CISA KEV / EPSS). --no-enrich pour rester hors-ligne.':
      'Enrich CVEs (CISA KEV / EPSS). --no-enrich to stay offline.',
  'Format de sortie : pdf (défaut), asciidoc, json.':
      'Output format: pdf (default), asciidoc, json.',
  'Fichier de sortie. Requis pour pdf/asciidoc ; json sur stdout si omis.':
      'Output file. Required for pdf/asciidoc; json on stdout if omitted.',
  'cra: fichier SBOM introuvable : {sbomFile}':
      'cra: SBOM file not found: {sbomFile}',
  'cra: --output <fichier> est requis pour --format {format}.':
      'cra: --output <file> is required for --format {format}.',
  'cra: impossible de lire le SBOM : {e}': 'cra: unable to read the SBOM: {e}',
  'cra: format SBOM non reconnu (CycloneDX / SPDX attendu).':
      'cra: unrecognised SBOM format (CycloneDX / SPDX expected).',
  'cra: fichier de config introuvable : {configPath}':
      'cra: config file not found: {configPath}',
  'cra: aucun scanner disponible — rapport produit sans inventaire de vulnérabilités (utilisez --no-scan pour l\'assumer).':
      'cra: no scanner available — report produced without a vulnerability inventory (use --no-scan to accept this).',
  'cra : {vex} CVE écartée(s) par VEX, {ignored} ignorée(s).':
      'cra: {vex} CVE(s) dropped by VEX, {ignored} ignored.',
  'Rapport CRA (JSON) écrit → {outputPath}':
      'CRA report (JSON) written → {outputPath}',
  'Rapport CRA (AsciiDoc) écrit → {adocPath}':
      'CRA report (AsciiDoc) written → {adocPath}',
  'Rapport CRA (PDF) écrit → {outputPath}':
      'CRA report (PDF) written → {outputPath}',
  'cra: asciidoctor-pdf a échoué (code {exitCode}) — AsciiDoc conservé → {adocPath}':
      'cra: asciidoctor-pdf failed (code {exitCode}) — AsciiDoc kept → {adocPath}',
  'cra: asciidoctor-pdf introuvable — PDF non généré, AsciiDoc conservé → {adocPath}':
      'cra: asciidoctor-pdf not found — PDF not generated, AsciiDoc kept → {adocPath}',
  'Verdict (périmètre vérifié) : ': 'Verdict (verified scope): ',
  'conforme': 'compliant',
  'conforme avec réserves': 'compliant with reservations',
  'NON conforme ({blockers} point(s) bloquant(s))':
      'NON-compliant ({blockers} blocking item(s))',
  'non évalué': 'not assessed',
  'sbom_generator cra – Rapport de conformité Cyber Resilience Act (UE 2024/2847).\n\nPérimètre : éléments vérifiables automatiquement uniquement — format et\ncomplétude du SBOM (Annexe I §2 point 1, BSI TR-03183-2, éléments minimaux\nNTIA), inventaire des vulnérabilités connues et disponibilité des correctifs\n(Annexe I §2 points 1-2), vulnérabilités activement exploitées (art. 14).\nLes autres obligations du CRA relèvent du fabricant. Ce rapport n\'est pas une\ndéclaration de conformité.\n\nUsage:\n  sbom-generator cra --sbom sbom.cdx.json --format pdf -o rapport-cra.pdf\n  sbom-generator cra --sbom sbom.cdx.json --config cra.yaml -o rapport-cra.pdf\n  sbom-generator cra --sbom sbom.cdx.json --no-scan --format json\n\nFichier cra.yaml (toutes les clés sont facultatives) :\n  manufacturer: "ACME Corp"\n  product: "WidgetOS"\n  product_version: "3.2.1"\n  support_until: "2030-12-31"\n  vulnerability_contact: "security@acme.example"\n  cvd_policy_url: "https://acme.example/security/policy"\n\n{usage}\n\nCodes de retour : 0 = conforme / conforme avec réserves, 2 = non conforme\n(au moins un point bloquant sur le périmètre vérifié).\n':
      'sbom_generator cra – Cyber Resilience Act compliance report (EU 2024/2847).\n\nScope: only automatically verifiable items — SBOM format and completeness\n(Annex I §2 point 1, BSI TR-03183-2, NTIA minimum elements), inventory of\nknown vulnerabilities and availability of fixes (Annex I §2 points 1-2),\nactively exploited vulnerabilities (art. 14). The other CRA obligations\nremain the manufacturer\'s responsibility. This report is not a declaration\nof conformity.\n\nUsage:\n  sbom-generator cra --sbom sbom.cdx.json --format pdf -o cra-report.pdf\n  sbom-generator cra --sbom sbom.cdx.json --config cra.yaml -o cra-report.pdf\n  sbom-generator cra --sbom sbom.cdx.json --no-scan --format json\n\ncra.yaml file (all keys are optional):\n  manufacturer: "ACME Corp"\n  product: "WidgetOS"\n  product_version: "3.2.1"\n  support_until: "2030-12-31"\n  vulnerability_contact: "security@acme.example"\n  cvd_policy_url: "https://acme.example/security/policy"\n\n{usage}\n\nExit codes: 0 = compliant / compliant with reservations, 2 = non-compliant\n(at least one blocking item within the verified scope).\n',
  'En mode strict, les champs recommandés (mais non obligatoires) génèrent aussi des erreurs.':
      'In strict mode, recommended (but not mandatory) fields also raise errors.',
  'Valide aussi le document par rapport au schéma JSON officiel\n(CycloneDX 1.4–1.7, SPDX 2.3, SPDX 3.0), embarqué dans le\nprogramme. --no-schema : contrôles structurels seuls.\nLes fichiers SPDX 3.0 générés avant la 1.10.5 (ancien format)\ndonnent un avertissement.':
      'Also validates the document against the official JSON schema\n(CycloneDX 1.4–1.7, SPDX 2.3, SPDX 3.0), embedded in the\nprogram. --no-schema: structural checks only.\nSPDX 3.0 files generated before 1.10.5 (legacy format) only\nraise a warning.',
  'Format du rapport : text (défaut) ou json (stdout, lisible par\nune machine).':
      'Report format: text (default) or json (stdout, machine-readable).',
  'validate: au moins un fichier SBOM requis.':
      'validate: at least one SBOM file is required.',
  '{path} : ERREUR — fichier introuvable': '{path} : ERROR — file not found',
  'fichier introuvable': 'file not found',
  '{path} : ERREUR — JSON invalide : {e}': '{path} : ERROR — invalid JSON: {e}',
  'JSON invalide : {e}': 'invalid JSON: {e}',
  'format inconnu': 'unknown format',
  '[schéma] ': '[schema] ',
  'ancien format SPDX 3.0 non conforme au schéma officiel (généré avant la 1.10.5) : régénérez le SBOM.':
      'legacy SPDX 3.0 format not conforming to the official schema (generated before 1.10.5): regenerate the SBOM.',
  'le document ne satisfait pas le schéma JSON officiel SPDX 3.0.':
      'the document does not satisfy the official SPDX 3.0 JSON schema.',
  'aucun schéma embarqué pour cette version : contrôle de schéma ignoré':
      'no embedded schema for this version: schema check skipped',
  '{path} : {label} — {errors} erreur(s) :':
      '{path} : {label} — {errors} error(s):',
  'Aucun indicateur de format reconnu. Attendu : bomFormat="CycloneDX", spdxVersion ou @context/@graph.':
      'No recognised format indicator. Expected: bomFormat="CycloneDX", spdxVersion or @context/@graph.',
  'bomFormat doit être "CycloneDX"': 'bomFormat must be "CycloneDX"',
  'specVersion manquant': 'specVersion missing',
  '[strict] version manquant': '[strict] version missing',
  '[strict] serialNumber manquant': '[strict] serialNumber missing',
  'components doit être un tableau JSON': 'components must be a JSON array',
  'composant[{i}] : champ name manquant ou vide':
      'component[{i}]: name field missing or empty',
  'composant[{i}] ({name}) : champ type manquant':
      'component[{i}] ({name}): type field missing',
  '[strict] composant[{i}] ({name}) : version manquante':
      '[strict] component[{i}] ({name}): version missing',
  'spdxVersion manquant ou invalide (attendu : SPDX-2.x)':
      'spdxVersion missing or invalid (expected: SPDX-2.x)',
  'SPDXID doit être "SPDXRef-DOCUMENT"': 'SPDXID must be "SPDXRef-DOCUMENT"',
  'name manquant': 'name missing',
  'dataLicense manquant': 'dataLicense missing',
  '[strict] creationInfo manquant': '[strict] creationInfo missing',
  'packages[{i}] : SPDXID manquant': 'packages[{i}]: SPDXID missing',
  'packages[{i}] : name manquant': 'packages[{i}]: name missing',
  '[strict] packages[{i}] ({name}) : versionInfo manquant':
      '[strict] packages[{i}] ({name}): versionInfo missing',
  '@context manquant': '@context missing',
  '@graph manquant': '@graph missing',
  '@graph doit être un tableau JSON': '@graph must be a JSON array',
  '@graph ne contient pas d\'élément SpdxDocument':
      '@graph contains no SpdxDocument element',
  '[strict] @graph[{i}] : spdxId manquant':
      '[strict] @graph[{i}]: spdxId missing',
  'Dossier où mémoriser le dernier scan de chaque SBOM (créé si\nabsent). Le premier passage établit l\'état initial.':
      'Directory holding the last scan of each SBOM (created if\nmissing). The first pass records the initial state.',
  'Scanner de vulnérabilités.': 'Vulnerability scanner.',
  'Rescanne en boucle à cet intervalle (90s, 30m, 6h, 1d).\nOmis : un seul passage (adapté à cron / CI).':
      'Rescan in a loop at this interval (90s, 30m, 6h, 1d).\nOmitted: a single pass (suited to cron / CI).',
  'Commande shell lancée pour chaque SBOM ayant de nouvelles CVE.\nVariables : SBOMGEN_WATCH_SBOM, SBOMGEN_WATCH_NEW (nombre),\nSBOMGEN_WATCH_REPORT (JSON des nouveaux constats). Si elle\néchoue, l\'état n\'est pas mis à jour : nouvelle tentative au\npassage suivant.':
      'Shell command run for each SBOM with new CVEs.\nVariables: SBOMGEN_WATCH_SBOM, SBOMGEN_WATCH_NEW (count),\nSBOMGEN_WATCH_REPORT (JSON of the new findings). If it\nfails the state is not updated: retried on the next pass.',
  'Option transmise telle quelle à `scan` (répétable), p. ex.\n--scan-arg=--no-enrich.':
      'Option passed as is to `scan` (repeatable), e.g.\n--scan-arg=--no-enrich.',
  'Sortie : text (défaut) ou json (un événement par ligne).':
      'Output: text (default) or json (one event per line).',
  'sbom_generator watch – Rescanne des SBOM et signale les nouvelles CVE.\n\nUsage:\n  sbom_generator watch sbom/ autre.cdx.json --state-dir .watch\n  sbom_generator watch sbom/ -d .watch --interval 6h --notify-cmd \'./alerte.sh\'\n\nChaque SBOM est scanné (`scan --format json`) puis comparé au scan précédent.\nUn dossier est parcouru récursivement (*.cdx.json, *.spdx.json, *.spdx3.jsonld).\n\n{usage}\n\nCodes de retour (un seul passage) :\n  0  Aucune nouvelle CVE\n  1  Erreur (usage, SBOM illisible, scan ou notification en échec)\n  3  Au moins une nouvelle CVE\n':
      'sbom_generator watch – Rescans SBOMs and reports new CVEs.\n\nUsage:\n  sbom_generator watch sbom/ other.cdx.json --state-dir .watch\n  sbom_generator watch sbom/ -d .watch --interval 6h --notify-cmd \'./alert.sh\'\n\nEach SBOM is scanned (`scan --format json`) and compared with its previous scan.\nA directory is searched recursively (*.cdx.json, *.spdx.json, *.spdx3.jsonld).\n\n{usage}\n\nExit codes (single pass):\n  0  No new CVE\n  1  Error (usage, unreadable SBOM, failed scan or notification)\n  3  At least one new CVE\n',
  'watch: au moins un SBOM ou dossier requis.':
      'watch: at least one SBOM or directory is required.',
  'watch: aucun SBOM trouvé.': 'watch: no SBOM found.',
  'erreur': 'error',
  'scan impossible (code {exitCode}) {err}':
      'scan failed (code {exitCode}) {err}',
  'état initial enregistré': 'initial state recorded',
  'aucune nouvelle CVE': 'no new CVE',
  '{resolved} corrigée(s)': '{resolved} resolved',
  'nouvelle(s) CVE': 'new CVE(s)',
  '--notify-cmd en échec (code {exitCode}) : état conservé':
      '--notify-cmd failed (code {exitCode}): state kept',
  'Bundle de signature (défaut : <sbom>.bundle, écrit par --sign).':
      'Signature bundle (default: <sbom>.bundle, written by --sign).',
  'Clé publique cosign (vérification à clé).':
      'cosign public key (key-based verification).',
  'Identité attendue du certificat (sans clé).':
      'Expected certificate identity (keyless).',
  'Identité du certificat, en expression régulière.':
      'Certificate identity, as a regular expression.',
  'Émetteur OIDC attendu du certificat (sans clé).':
      'Expected certificate OIDC issuer (keyless).',
  'Émetteur OIDC du certificat, en expression régulière.':
      'Certificate OIDC issuer, as a regular expression.',
  'Format du rapport : text (défaut) ou json (stdout).':
      'Report format: text (default) or json (stdout).',
  'verify: exactement un fichier SBOM requis.':
      'verify: exactly one SBOM file is required.',
  'verify: --key, ou --certificate-identity[-regexp] et --certificate-oidc-issuer[-regexp], requis.':
      'verify: --key, or --certificate-identity[-regexp] and --certificate-oidc-issuer[-regexp], required.',
  'signature valide': 'valid signature',
  'signature INVALIDE': 'INVALID signature',
  'SBOM ou bundle introuvable': 'SBOM or bundle not found',
  'cosign introuvable': 'cosign not found',
  'sbom_generator verify – Vérifie la signature cosign d\'un SBOM (cosign verify-blob).\n\nUsage:\n  sbom_generator verify sbom.cdx.json --key cosign.pub\n  sbom_generator verify sbom.cdx.json \\\n      --certificate-identity moi@exemple.org \\\n      --certificate-oidc-issuer https://accounts.google.com\n\nLe bundle est celui écrit par `--sign` (<sbom>.bundle). Requiert cosign.\n\n{usage}\n\nCodes de retour:\n  0  Signature valide\n  1  Erreur d\'usage, fichier ou cosign introuvable\n  2  Signature invalide\n':
      'sbom_generator verify – Verifies the cosign signature of an SBOM (cosign verify-blob).\n\nUsage:\n  sbom_generator verify sbom.cdx.json --key cosign.pub\n  sbom_generator verify sbom.cdx.json \\\n      --certificate-identity me@example.org \\\n      --certificate-oidc-issuer https://accounts.google.com\n\nThe bundle is the one written by `--sign` (<sbom>.bundle). Requires cosign.\n\n{usage}\n\nExit codes:\n  0  Valid signature\n  1  Usage error, file or cosign not found\n  2  Invalid signature\n',
  'sbom_generator validate – Vérifie la structure d\'un ou plusieurs fichiers SBOM.\n\nUsage:\n  sbom_generator validate <fichier1.cdx.json> [fichier2.spdx.json ...]\n\nFormats supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\n\n{usage}\n\nCodes de retour:\n  0  Tous les fichiers sont valides\n  1  Au moins un fichier est invalide ou introuvable\n':
      'sbom_generator validate – Checks the structure of one or more SBOM files.\n\nUsage:\n  sbom_generator validate <file1.cdx.json> [file2.spdx.json ...]\n\nSupported formats: CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\n\n{usage}\n\nExit codes:\n  0  All files are valid\n  1  At least one file is invalid or not found\n',
  'sbom_generator – Génère un SBOM à partir d\'une liste de paquets ou d\'une image de conteneur OCI.\n\nUsage:\n  dart run bin/sbom_generator.dart --input <file> [options]\n  dart run bin/sbom_generator.dart --image <ref>  [options]\n  dart run bin/sbom_generator.dart --image <ref> --input <file> [options]\n  dart run bin/sbom_generator.dart --binary <fichier> [options]\n\n{usage}\n\nFormat du fichier d\'entrée (--input) :\n  Une référence de paquet par ligne. Les lignes commençant par # sont ignorées.\n  Les références peuvent être mélangées :\n    • RPM : nom de paquet installé/NEVRA, ou chemin vers un fichier .rpm\n    • Wheel Python : chemin vers un fichier .whl\n    • Archive source : chemin vers un .tar, .tar.gz ou .tgz\n        - sdist Python (PKG-INFO présent) → PURL pkg:pypi/…\n        - Archive générique (sans métadonnées) → PURL pkg:generic/…\n    • Debian : chemin vers un fichier .deb\n    • requirements.txt : chemin vers un fichier de dépendances pip\n    • Manifestes/lockfiles : go.sum, go.mod, package-lock.json, yarn.lock,\n      pnpm-lock.yaml, Cargo.lock, composer.lock, Gemfile.lock,\n      uv.lock, poetry.lock, pdm.lock, Package.resolved, packages.lock.json,\n      *.deps.json, *.csproj, pom.xml, pubspec.lock, pubspec.yaml\n\nFormats d\'image OCI (--image) :\n    • Registre  : nginx:latest  ubuntu:22.04  myregistry.io/app@sha256:…\n    • Archive   : /chemin/image.tar        (docker save / skopeo docker-archive)\n    • OCI layout: /chemin/vers/oci_dir/    (dossier contenant index.json)\n\nExamples:\n  # CycloneDX depuis une image Docker Hub (via syft, défaut)\n  dart run bin/sbom_generator.dart --image nginx:latest -o nginx.cdx.json\n\n  # SPDX 2.3 depuis une archive tar, backend trivy\n  dart run bin/sbom_generator.dart --image ./ubuntu.tar --oci-tool trivy -f spdx -o sbom.spdx.json\n\n  # OCI layout directory, backend skopeo\n  dart run bin/sbom_generator.dart --image ./oci_layout/ --oci-tool skopeo -o sbom.cdx.json\n\n  # CycloneDX depuis une image Docker Hub, backend cdxgen\n  dart run bin/sbom_generator.dart --image nginx:latest --oci-tool cdxgen -o nginx.cdx.json\n\n  # Un SBOM par couche de l\'image (delta), en plus du global\n  dart run bin/sbom_generator.dart --image ./app.tar --per-layer -o out/app\n  dart run bin/sbom_generator.dart --image ./app.tar --per-layer --layer-mode rootfs -o out/app\n\n  # Combiner image OCI + liste de paquets supplémentaires\n  dart run bin/sbom_generator.dart --image nginx:latest -i extra_pkgs.txt -o sbom.cdx.json\n\n  # Multi-format en un seul passage\n  dart run bin/sbom_generator.dart --image nginx:latest -f cyclonedx,spdx,markdown -o sbom\n\n  # Depuis un fichier de paquets (mode classique)\n  dart run bin/sbom_generator.dart -i packages.txt -o sbom.cdx.json\n\n  # Binaire lié statiquement (ex. exécutable Go) — dépendances embarquées\n  # lues via syft (buildinfo Go / classifieur générique), sans dépôt/registre\n  dart run bin/sbom_generator.dart --binary /usr/local/bin/mon-app -o app.cdx.json\n':
      'sbom_generator – Generate an SBOM from a list of packages or an OCI container image.\n\nUsage:\n  dart run bin/sbom_generator.dart --input <file> [options]\n  dart run bin/sbom_generator.dart --image <ref>  [options]\n  dart run bin/sbom_generator.dart --image <ref> --input <file> [options]\n  dart run bin/sbom_generator.dart --binary <file> [options]\n\n{usage}\n\nInput file format (--input):\n  One package reference per line. Lines starting with # are ignored.\n  References can be mixed:\n    • RPM: installed package name/NEVRA, or path to a .rpm file\n    • Python wheel: path to a .whl file\n    • Source archive: path to a .tar, .tar.gz or .tgz file\n        - Python sdist (PKG-INFO present) → PURL pkg:pypi/…\n        - Generic archive (no metadata)   → PURL pkg:generic/…\n    • Debian: path to a .deb file\n    • requirements.txt: path to a pip requirements file\n    • Manifests/lockfiles: go.sum, go.mod, package-lock.json, yarn.lock,\n      pnpm-lock.yaml, Cargo.lock, composer.lock, Gemfile.lock,\n      uv.lock, poetry.lock, pdm.lock, Package.resolved, packages.lock.json,\n      *.deps.json, *.csproj, pom.xml, pubspec.lock, pubspec.yaml\n\nOCI image formats (--image):\n    • Registry  : nginx:latest  ubuntu:22.04  myregistry.io/app@sha256:…\n    • Archive   : /path/image.tar          (docker save / skopeo docker-archive)\n    • OCI layout: /path/to/oci_dir/        (directory containing index.json)\n\nExamples:\n  # CycloneDX from a Docker Hub image (via syft, default)\n  dart run bin/sbom_generator.dart --image nginx:latest -o nginx.cdx.json\n\n  # SPDX 2.3 from a tar archive, trivy backend\n  dart run bin/sbom_generator.dart --image ./ubuntu.tar --oci-tool trivy -f spdx -o sbom.spdx.json\n\n  # OCI layout directory, skopeo backend\n  dart run bin/sbom_generator.dart --image ./oci_layout/ --oci-tool skopeo -o sbom.cdx.json\n\n  # CycloneDX from a Docker Hub image, cdxgen backend\n  dart run bin/sbom_generator.dart --image nginx:latest --oci-tool cdxgen -o nginx.cdx.json\n\n  # One SBOM per image layer (delta), in addition to the global one\n  dart run bin/sbom_generator.dart --image ./app.tar --per-layer -o out/app\n  dart run bin/sbom_generator.dart --image ./app.tar --per-layer --layer-mode rootfs -o out/app\n\n  # Combine an OCI image + a list of extra packages\n  dart run bin/sbom_generator.dart --image nginx:latest -i extra_pkgs.txt -o sbom.cdx.json\n\n  # Multi-format in a single pass\n  dart run bin/sbom_generator.dart --image nginx:latest -f cyclonedx,spdx,markdown -o sbom\n\n  # From a package list file (classic mode)\n  dart run bin/sbom_generator.dart -i packages.txt -o sbom.cdx.json\n\n  # Statically linked binary (e.g. Go executable) — embedded dependencies\n  # read via syft (Go buildinfo / generic classifier), no repository/registry\n  dart run bin/sbom_generator.dart --binary /usr/local/bin/my-app -o app.cdx.json\n',
  'nom de paquet indéterminable à partir de "{path}" ; ignoré.':
      'cannot determine package name from "{path}"; skipping.',
  'Info : "{licenseFile}" trouvé dans "{last}" mais aucune licence SPDX connue n\'a pu être identifiée.':
      'Info: found "{licenseFile}" in "{last}" but could not identify a known SPDX license.',
  'Software Bill of Materials — Licences':
      'Software Bill of Materials — Licenses',
  'Paquet': 'Package',
  'Licence': 'License',
  '(inconnue)': '(unknown)',
  '== Supprimés par cette couche': '== Removed by this layer',
  '_Généré par sbom_generator — {packages} paquet(s)._':
      '_Generated by sbom_generator — {packages} package(s)._',
  'Cargo.lock introuvable : {path}': 'Cargo.lock not found: {path}',
  'composer.lock introuvable : {path}': 'composer.lock not found: {path}',
  'projet .NET introuvable : {path}': '.NET project not found: {path}',
  '{label} introuvable : {path}': '{label} not found: {path}',
  'version calculée ignorée pour {name} dans {path}':
      'computed version ignored for {name} in {path}',
  'lockfile Python introuvable : {path}': 'Python lockfile not found: {path}',
  'Package.resolved introuvable : {path}': 'Package.resolved not found: {path}',
  'analyse impossible de {path} : {e}': 'cannot parse {path}: {e}',
  '[.verdict-ok]*Conforme*': '[.verdict-ok]*Compliant*',
  '[.verdict-watch]*Partiel*': '[.verdict-watch]*Partial*',
  '[.verdict-urgent]*Non conforme*': '[.verdict-urgent]*Non-compliant*',
  '[.muted]_Non évalué_': '[.muted]_Not assessed_',
  'Nom du composant': 'Component name',
  'Fournisseur / créateur': 'Supplier / creator',
  'Identifiant unique (PURL / CPE)': 'Unique identifier (PURL / CPE)',
  'Empreinte cryptographique (hash)': 'Cryptographic hash',
  'Nom du fournisseur': 'Supplier name',
  'Version du composant': 'Component version',
  'Autres identifiants uniques': 'Other unique identifiers',
  'Relation de dépendance': 'Dependency relationship',
  'Auteur des données SBOM': 'Author of SBOM data',
  'Horodatage': 'Timestamp',
  'Le SBOM n\'est pas dans un format d\'usage courant lisible par machine (Annexe I §2 point 1).':
      'The SBOM is not in a commonly used machine-readable format (Annex I §2 point 1).',
  'Le SBOM ne décrit aucune relation de dépendance (Annexe I §2 point 1 : au moins les dépendances de premier niveau).':
      'The SBOM describes no dependency relationship (Annex I §2 point 1: at least the first-level dependencies).',
  'Champ SBOM obligatoire insuffisamment renseigné : {label} ({coverage}).':
      'Mandatory SBOM field insufficiently filled in: {label} ({coverage}).',
  '{cvesWithoutFix} vulnérabilité(s) connue(s) sans correctif disponible (Annexe I §2 point 2).':
      '{cvesWithoutFix} known vulnerability(ies) without an available fix (Annex I §2 point 2).',
  '{kevCves} vulnérabilité(s) activement exploitée(s) — notification à l\'ENISA / au CSIRT coordinateur requise sous 24 h (art. 14).':
      '{kevCves} actively exploited vulnerability(ies) — notification to ENISA / the coordinating CSIRT required within 24 h (art. 14).',
  'Conforme sur le périmètre vérifié automatiquement (SBOM et vulnérabilités connues).':
      'Compliant within the automatically verified scope (SBOM and known vulnerabilities).',
  'Conforme avec réserves sur le périmètre vérifié : des champs SBOM sont incomplets ou l\'analyse de vulnérabilités n\'a pas été exécutée.':
      'Compliant with reservations within the verified scope: some SBOM fields are incomplete or the vulnerability scan was not run.',
  'Non conforme sur le périmètre vérifié : {blockers} point(s) bloquant(s) — voir la conclusion.':
      'Non-compliant within the verified scope: {blockers} blocking item(s) — see the conclusion.',
  'Non évalué.': 'Not assessed.',
  '[.verdict-urgent]*non renseigné*': '[.verdict-urgent]*not provided*',
  '= Rapport de conformité: Cyber Resilience Act':
      '= Compliance report: Cyber Resilience Act',
  ':toc-title: Sommaire': ':toc-title: Contents',
  '== Portée et limites': '== Scope and limits',
  'Ce rapport ne couvre que les exigences du Règlement (UE) 2024/2847 *vérifiables automatiquement* à partir d\'un SBOM et d\'une analyse de vulnérabilités connues : format et complétude du SBOM (Annexe I §2 point 1 ; BSI TR-03183-2 ; éléments minimaux NTIA), inventaire des vulnérabilités et disponibilité des correctifs (Annexe I §2 points 1-2), vulnérabilités activement exploitées (art. 14).':
      'This report only covers the requirements of Regulation (EU) 2024/2847 that can be *verified automatically* from an SBOM and a scan of known vulnerabilities: SBOM format and completeness (Annex I §2 point 1; BSI TR-03183-2; NTIA minimum elements), inventory of vulnerabilities and availability of fixes (Annex I §2 points 1-2), actively exploited vulnerabilities (art. 14).',
  'Les autres obligations du CRA — mécanisme de diffusion sécurisé des mises à jour, politique de divulgation coordonnée *effective*, conception sûre par défaut, tests et revues réguliers, notifications réglementaires, déclaration UE de conformité — relèvent du fabricant et ne sont pas évaluées ici. Ce document n\'est pas une déclaration de conformité.':
      'The other CRA obligations — secure update distribution mechanism, *effective* coordinated vulnerability disclosure policy, secure by default design, regular tests and reviews, regulatory notifications, EU declaration of conformity — are the manufacturer\'s responsibility and are not assessed here. This document is not a declaration of conformity.',
  '== Résumé exécutif': '== Executive summary',
  '*SBOM évalué*': '*Assessed SBOM*',
  'composants': 'components',
  '*Analyse de vulnérabilités*': '*Vulnerability scan*',
  'non exécutée': 'not run',
  'h| Champs SBOM conformes h| Éléments NTIA h| Vuln. sans correctif h| CVE exploitées (KEV)':
      'h| Compliant SBOM fields h| NTIA elements h| Vulns. without fix h| Exploited CVEs (KEV)',
  'Verdict (périmètre vérifié)': 'Verdict (verified scope)',
  '== Identification du produit': '== Product identification',
  'CRA art. 13 §§ 8, 15-19 et Annexe II — informations à fournir aux utilisateurs.':
      'CRA art. 13 §§ 8, 15-19 and Annex II — information to be provided to users.',
  '| Élément | Valeur': '| Item | Value',
  'Fabricant': 'Manufacturer',
  'Produit': 'Product',
  'Fin de la période de support': 'End of support period',
  'Contact de signalement des vulnérabilités':
      'Vulnerability reporting contact',
  'Politique de divulgation coordonnée':
      'Coordinated vulnerability disclosure policy',
  '== SBOM — format et contenu': '== SBOM — format and content',
  '=== Format lisible par machine (Annexe I §2 point 1)':
      '=== Machine-readable format (Annex I §2 point 1)',
  'Format détecté': 'Detected format',
  '[.verdict-ok]*format d\'usage courant, lisible par machine*':
      '[.verdict-ok]*commonly used, machine-readable format*',
  '[.verdict-urgent]*format non reconnu*':
      '[.verdict-urgent]*unrecognised format*',
  'Relations de dépendance': 'Dependency relationships',
  '(exigence : au moins les dépendances de premier niveau)':
      '(requirement: at least the first-level dependencies)',
  '=== Champs de données par composant (BSI TR-03183-2)':
      '=== Data fields per component (BSI TR-03183-2)',
  '_Aucun composant listé dans le SBOM._': '_No component listed in the SBOM._',
  '| Champ | Obligatoire | Couverture | Statut':
      '| Field | Mandatory | Coverage | Status',
  'oui': 'yes',
  'recommandé': 'recommended',
  'Composants incomplets (échantillon) :': 'Incomplete components (sample):',
  '=== Métadonnées du document (NTIA)': '=== Document metadata (NTIA)',
  '| Élément | Statut': '| Item | Status',
  'Auteur du SBOM': 'SBOM author',
  'Composant primaire déclaré': 'Primary component declared',
  '== Éléments minimaux NTIA (2021)': '== NTIA minimum elements (2021)',
  'Score `sbomqs` (au moment de l\'évaluation) :':
      '`sbomqs` score (at assessment time):',
  '== Gestion des vulnérabilités (Annexe I §2)':
      '== Vulnerability handling (Annex I §2)',
  'L\'analyse de vulnérabilités n\'a pas été exécutée. L\'inventaire des vulnérabilités connues (Annexe I §2 point 1) et la disponibilité des correctifs (point 2) ne peuvent pas être attestés. Relancer avec l\'option `--scan`.':
      'The vulnerability scan was not run. The inventory of known vulnerabilities (Annex I §2 point 1) and the availability of fixes (point 2) cannot be attested. Re-run with the `--scan` option.',
  '=== Inventaire des vulnérabilités connues (point 1)':
      '=== Inventory of known vulnerabilities (point 1)',
  'Outils': 'Tools',
  'Total : *{totalCves}* CVE uniques — {critical} critiques, {high} élevées, {medium} moyennes, {low} faibles.':
      'Total: *{totalCves}* unique CVEs — {critical} critical, {high} high, {medium} medium, {low} low.',
  '=== Disponibilité des correctifs (point 2)':
      '=== Availability of fixes (point 2)',
  '[.verdict-ok]*Toutes les vulnérabilités connues disposent d\'une version corrigée.*':
      '[.verdict-ok]*All known vulnerabilities have a fixed version.*',
  '[.verdict-urgent]*{noFix} vulnérabilité(s) sans correctif disponible* — à adresser et remédier sans délai (Annexe I §2 point 2) :':
      '[.verdict-urgent]*{noFix} vulnerability(ies) without an available fix* — to be addressed and remedied without delay (Annex I §2 point 2):',
  '=== Vulnérabilités activement exploitées — notification réglementaire (art. 14)':
      '=== Actively exploited vulnerabilities — regulatory notification (art. 14)',
  '[.verdict-ok]*Aucune vulnérabilité du produit n\'est au catalogue CISA KEV des vulnérabilités activement exploitées.*':
      '[.verdict-ok]*No vulnerability of the product is in the CISA KEV catalog of actively exploited vulnerabilities.*',
  '[.verdict-urgent]*{kev} vulnérabilité(s) activement exploitée(s) (catalogue CISA KEV).*':
      '[.verdict-urgent]*{kev} actively exploited vulnerability(ies) (CISA KEV catalog).*',
  '| CVE | Ajoutée au KEV | Correctif disponible':
      '| CVE | Added to KEV | Fix available',
  '[.verdict-urgent]*non*': '[.verdict-urgent]*no*',
  'CRA art. 14 : le fabricant notifie au CSIRT désigné comme coordinateur et à l\'ENISA toute vulnérabilité activement exploitée contenue dans le produit — *alerte précoce sous 24 h*, notification sous 72 h, rapport final sous 14 jours après mise à disposition d\'une mesure corrective ou d\'atténuation.':
      'CRA art. 14: the manufacturer notifies the CSIRT designated as coordinator and ENISA of any actively exploited vulnerability contained in the product — *early warning within 24 h*, notification within 72 h, final report within 14 days after a corrective or mitigating measure is made available.',
  '== Exigences relevant du fabricant (non évaluées)':
      '== Manufacturer requirements (not assessed)',
  'Éléments à attester par le fabricant dans sa documentation technique (Annexe VII) et sa déclaration UE de conformité (Annexe V).':
      'Items to be attested by the manufacturer in its technical documentation (Annex VII) and its EU declaration of conformity (Annex V).',
  '| Exigence | Élément fourni': '| Requirement | Item provided',
  '_à attester_': '_to be attested_',
  'Politique de divulgation coordonnée effective (Annexe I §2 point 5)':
      'Effective coordinated vulnerability disclosure policy (Annex I §2 point 5)',
  'URL fournie': 'URL provided',
  'Adresse de signalement des vulnérabilités (point 6)':
      'Vulnerability reporting address (point 6)',
  'fournie': 'provided',
  'Diffusion des correctifs sans délai et gratuite (point 8)':
      'Fixes distributed without delay and free of charge (point 8)',
  'Mécanisme de diffusion sécurisé des mises à jour (Annexe I §1 point 2 k)':
      'Secure update distribution mechanism (Annex I §1 point 2 k)',
  'Tests et revues réguliers de sécurité (point 3)':
      'Regular security tests and reviews (point 3)',
  'Divulgation publique des vulnérabilités corrigées (point 4)':
      'Public disclosure of fixed vulnerabilities (point 4)',
  'Conception sûre par défaut (Annexe I §1)':
      'Secure by default design (Annex I §1)',
  'Points bloquants sur le périmètre vérifié :':
      'Blocking items within the verified scope:',
  '_Rapport généré par sbom-generator le {_frDate}. Périmètre automatique uniquement — ne se substitue pas à une évaluation de conformité par le fabricant ou un organisme notifié._':
      '_Report generated by sbom-generator on {_frDate}. Automatic scope only — does not replace a conformity assessment by the manufacturer or a notified body._',
  'specVersion non supporté : "{specVersion}" (valides : {supportedSpecVersions})':
      'unsupported specVersion: "{specVersion}" (valid: {supportedSpecVersions})',
  'tlp / citationSource / patentsByPackageName nécessitent specVersion="1.7" (CycloneDX 1.6 n\'a pas ces champs : le schéma 1.6 rejette les propriétés inconnues)':
      'tlp / citationSource / patentsByPackageName require specVersion="1.7" (CycloneDX 1.6 lacks these fields: the 1.6 schema rejects unknown properties)',
  'tlp invalide : "{tlp}" (valides : {validTlpClassifications})':
      'invalid tlp: "{tlp}" (valid: {validTlpClassifications})',
  'jurisdiction de brevet invalide : "{jurisdiction}" (2 lettres majuscules attendues, ex: US)':
      'invalid patent jurisdiction: "{jurisdiction}" (2 uppercase letters expected, e.g. US)',
  'legalStatus de brevet invalide : "{legalStatus}" (valides : {validLegalStatuses})':
      'invalid patent legalStatus: "{legalStatus}" (valid: {validLegalStatuses})',
  'assertionType de brevet invalide : "{assertionType}" (valides : {validAssertionTypes})':
      'invalid patent assertionType: "{assertionType}" (valid: {validAssertionTypes})',
  'lecture impossible de "{path}"': 'cannot read "{path}"',
  'aucun champ Package dans "{path}"': 'no Package field in "{path}"',
  'Gemfile.lock introuvable : {path}': 'Gemfile.lock not found: {path}',
  'fichier go.sum introuvable : {path}': 'go.sum file not found: {path}',
  'fichier go.mod introuvable : {path}': 'go.mod file not found: {path}',
  'Non spécifiée': 'Not specified',
  'Supprimés par cette couche': 'Removed by this layer',
  'fr': 'en',
  'Généré le': 'Generated on',
  'composant(s)': 'component(s)',
  'Composants': 'Components',
  'Écosystèmes': 'Ecosystems',
  'Licences distinctes': 'Distinct licenses',
  'Sans licence': 'No license',
  'Licences (top 15)': 'Licenses (top 15)',
  'Filtrer par nom, version, licence…': 'Filter by name, version, license…',
  'Tous les types': 'All types',
  'Nom': 'Name',
  'Type': 'Type',
  'Rapport généré par': 'Report generated by',
  'manifest.json inattendu (tableau attendu)':
      'unexpected manifest.json (array expected)',
  'layout OCI sans manifeste d\'image exploitable : {dir}':
      'OCI layout without a usable image manifest: {dir}',
  'tar de la couche {index} introuvable : {blob}':
      'tar of layer {index} not found: {blob}',
  'couche': 'layer',
  '    avertissement tar : {first}': '    tar warning: {first}',
  'au total': 'in total',
  'impossible de déterminer les coordonnées Maven de "{path}" (pas de META-INF/maven/*/*/pom.properties exploitable, et aucun suffixe de version reconnaissable dans le nom de fichier)':
      'cannot determine the Maven coordinates of "{path}" (no usable META-INF/maven/*/*/pom.properties, and no recognisable version suffix in the file name)',
  'Rapport de licences': 'License report',
  '== Résumé': '== Summary',
  '| Indicateur | Valeur': '| Indicator | Value',
  'Paquets analysés': 'Packages analysed',
  'Licences (expressions) distinctes': 'Distinct licenses (expressions)',
  'Paquets sous licence copyleft fort (GPL/AGPL)':
      'Packages under strong copyleft license (GPL/AGPL)',
  'Paquets sous licence copyleft faible (LGPL/MPL/EPL/CDDL/CPL/EUPL)':
      'Packages under weak copyleft license (LGPL/MPL/EPL/CDDL/CPL/EUPL)',
  'Paquets sans licence détectée': 'Packages with no detected license',
  'Licences copyleft fort détectées ({strongCopyleftPackages} paquet(s)) — la redistribution du logiciel combiné peut être soumise à obligation de publication du code source : {strongCopyleftTokens}.':
      'Strong copyleft licenses detected ({strongCopyleftPackages} package(s)) — redistribution of the combined software may be subject to a source code publication obligation: {strongCopyleftTokens}.',
  '{unknown} paquet(s) sans licence détectée, à vérifier manuellement :':
      '{unknown} package(s) with no detected license, to be checked manually:',
  '== Détail par licence': '== Details by license',
  '_Généré par sbom_generator — {packagesLen} paquet(s), {groups} licence(s) distincte(s)._':
      '_Generated by sbom_generator — {packagesLen} package(s), {groups} distinct license(s)._',
  ' [copyleft fort]': ' [strong copyleft]',
  ' [copyleft faible]': ' [weak copyleft]',
  '## Résumé': '## Summary',
  '| Indicateur | Valeur |': '| Indicator | Value |',
  '> **Attention** — licences copyleft fort détectées ({strongCopyleftPackages} paquet(s)) : la redistribution du logiciel combiné peut être soumise à obligation de publication du code source : {strongCopyleftTokens}.':
      '> **Warning** — strong copyleft licenses detected ({strongCopyleftPackages} package(s)): redistribution of the combined software may be subject to a source code publication obligation: {strongCopyleftTokens}.',
  '> **À vérifier** — {unknown} paquet(s) sans licence détectée :':
      '> **To check** — {unknown} package(s) with no detected license:',
  '## Détail par licence': '## Details by license',
  '_Généré par sbom_generator — {totalPackages} paquet(s), {groups} licence(s) distincte(s)._':
      '_Generated by sbom_generator — {totalPackages} package(s), {groups} distinct license(s)._',
  'Résumé': 'Summary',
  '<p class="warn"><strong>Attention</strong> — licences copyleft fort détectées ({strongCopyleftPackages} paquet(s)) : la redistribution du logiciel combiné peut être soumise à obligation de publication du code source : {strongCopyleftTokens}.</p>':
      '<p class="warn"><strong>Warning</strong> — strong copyleft licenses detected ({strongCopyleftPackages} package(s)): redistribution of the combined software may be subject to a source code publication obligation: {strongCopyleftTokens}.</p>',
  '<div class="note"><strong>À vérifier</strong> — {unknown} paquet(s) sans licence détectée :<ul>':
      '<div class="note"><strong>To check</strong> — {unknown} package(s) with no detected license:<ul>',
  'Détail par licence': 'Details by license',
  'copyleft fort': 'strong copyleft',
  'copyleft faible': 'weak copyleft',
  '<p><em>Généré par sbom_generator — {totalPackages} paquet(s), {groups} licence(s) distincte(s).</em></p>':
      '<p><em>Generated by sbom_generator — {totalPackages} package(s), {groups} distinct license(s).</em></p>',
  'Architecture': 'Architecture',
  '## Supprimés par cette couche': '## Removed by this layer',
  'pom.xml introuvable : {path}': 'pom.xml not found: {path}',
  '{location} : analyse impossible ({e})': '{location}: analysis failed ({e})',
  'python3 introuvable : impossible de descendre dans {label}.':
      'python3 not found: cannot descend into {label}.',
  '{label} : extraction impossible ({err})':
      '{label}: extraction failed ({err})',
  '{label} : sortie d\'extraction illisible':
      '{label}: unreadable extraction output',
  'package-lock.json introuvable : {path}':
      'package-lock.json not found: {path}',
  'Outil OCI inconnu : {tool}': 'Unknown OCI tool: {tool}',
  'trivy : attribution des couches de {ref}…':
      'trivy: attributing the layers of {ref}…',
  'syft : analyse de toutes les couches de {ref}…':
      'syft: analysing all the layers of {ref}…',
  '--layer-mode metadata non pris en charge par {tool}':
      '--layer-mode metadata is not supported by {tool}',
  'aucune couche trouvée dans {imageRef}': 'no layer found in {imageRef}',
  'extraction de {ref} échouée : {stderr}':
      'extraction of {ref} failed: {stderr}',
  '{ref} : ni manifest.json ni index.json — archive d\'image non reconnue':
      '{ref}: neither manifest.json nor index.json — unrecognised image archive',
  'un binaire autonome n\'a pas de couches':
      'a standalone binary has no layers',
  'OCI : décompression de {imageRef}…': 'OCI: decompressing {imageRef}…',
  'Décompression de {imageRef} échouée : {stderr}':
      'Decompression of {imageRef} failed: {stderr}',
  'OCI : gzip direct détecté, utilisation de {step1}':
      'OCI: direct gzip detected, using {step1}',
  'Format .tgz non reconnu : manifest.json absent et aucun .tar imbriqué trouvé. Contenu : {take}':
      'Unrecognised .tgz format: manifest.json missing and no nested .tar found. Content: {take}',
  'OCI : tar-de-tar détecté, extraction de {inner}…':
      'OCI: nested tar detected, extracting {inner}…',
  'Extraction du tar imbriqué ({inner}) échouée : {stderr}':
      'Extraction of the nested tar ({inner}) failed: {stderr}',
  'syft : analyse de {syftRef}…': 'syft: analysing {syftRef}…',
  'syft a échoué (code {exitCode}) : {stderr}':
      'syft failed (code {exitCode}): {stderr}',
  'syft : impossible de parser le JSON : {e}':
      'syft: unable to parse the JSON: {e}',
  'trivy : analyse de {imageRef}…': 'trivy: analysing {imageRef}…',
  'trivy a échoué (code {exitCode}) : {stderr}':
      'trivy failed (code {exitCode}): {stderr}',
  'trivy : impossible de parser le JSON : {e}':
      'trivy: unable to parse the JSON: {e}',
  'skopeo : aucune base de paquets reconnue dans les layers.':
      'skopeo: no recognised package database in the layers.',
  'skopeo : copie de {src}…': 'skopeo: copying {src}…',
  'skopeo copy a échoué :\n  {n}': 'skopeo copy failed:\n  {n}',
  'skopeo : base dpkg trouvée': 'skopeo: dpkg database found',
  'skopeo : base RPM trouvée': 'skopeo: RPM database found',
  'skopeo : base APK trouvée': 'skopeo: APK database found',
  'skopeo : aucun manifest dans le layout OCI':
      'skopeo: no manifest in the OCI layout',
  '  Warning (tar layer {i}) : {firstErr}':
      '  Warning (tar layer {i}): {firstErr}',
  'skopeo/rpm : base RPM trouvée mais vide dans {rootDir}':
      'skopeo/rpm: RPM database found but empty in {rootDir}',
  'skopeo : requête RPM sur {dbPath}': 'skopeo: RPM query on {dbPath}',
  'skopeo/rpm : échec (code {exitCode}) : {trim}':
      'skopeo/rpm: failed (code {exitCode}): {trim}',
  'skopeo : {jarFiles} JARs trouvés, extraction Maven…':
      'skopeo: {jarFiles} JARs found, Maven extraction…',
  'skopeo : {packages} paquets Maven extraits':
      'skopeo: {packages} Maven packages extracted',
  'skopeo : {metaFiles} métadonnées Python trouvées…':
      'skopeo: {metaFiles} Python metadata files found…',
  'skopeo : {packages} paquets Python extraits':
      'skopeo: {packages} Python packages extracted',
  'skopeo : {pkgFiles} package.json npm trouvés…':
      'skopeo: {pkgFiles} npm package.json files found…',
  'skopeo : {packages} paquets npm extraits':
      'skopeo: {packages} npm packages extracted',
  'cdxgen : analyse de {target}…': 'cdxgen: analysing {target}…',
  'cdxgen a échoué (code {exitCode}) : {stderr}':
      'cdxgen failed (code {exitCode}): {stderr}',
  'cdxgen : aucune sortie JSON reçue.': 'cdxgen: no JSON output received.',
  'cdxgen : impossible de parser le JSON : {e}':
      'cdxgen: unable to parse the JSON: {e}',
  'pnpm-lock.yaml introuvable : {path}': 'pnpm-lock.yaml not found: {path}',
  'policy: sbomqs introuvable — vérification qualité ignorée.':
      'policy: sbomqs not found — quality check skipped.',
  'sbomqs : évaluation de {sbomPath}…': 'sbomqs: assessing {sbomPath}…',
  'sbomqs: échec (code {exitCode})': 'sbomqs: failed (code {exitCode})',
  'pubspec.lock introuvable : {path}': 'pubspec.lock not found: {path}',
  'pubspec.yaml introuvable : {path}': 'pubspec.yaml not found: {path}',
  'fichier non reconnu : attendu un `scan --format json` ou une session de la GUI':
      'unrecognised file: expected a `scan --format json` output or a GUI session',
  'fichier requirements introuvable : {path}':
      'requirements file not found: {path}',
  'interrogation impossible de "{packageRef}"': 'cannot query "{packageRef}"',
  'sortie vide pour "{packageRef}"': 'empty output for "{packageRef}"',
  'sortie de requête inattendue pour "{packageRef}" : {line}':
      'unexpected query output for "{packageRef}": {line}',
  'Fichier introuvable : {path}': 'File not found: {path}',
  'Impossible de parser "{path}" : {e}': 'Unable to parse "{path}": {e}',
  'Aucun changement détecté.': 'No change detected.',
  'ajouté(s)': 'added',
  'supprimé(s)': 'removed',
  'mis à jour': 'updated',
  'Ajoutés': 'Added',
  'Supprimés': 'Removed',
  'Mis à jour': 'Updated',
  'Modifiés (même version)': 'Modified (same version)',
  'Couches': 'Layers',
  'couche supprimée': 'layer removed',
  'couche ajoutée': 'layer added',
  'licence': 'license',
  'empreintes': 'hashes',
  'fournisseur': 'supplier',
  'Au moins un SBOM requis': 'At least one SBOM is required',
  'Format SBOM non reconnu dans le fichier fourni.':
      'Unrecognised SBOM format in the given file.',
  'ligne {i} ignorée (identifiant attendu en premier)':
      'line {i} skipped (identifier expected first)',
  'ligne {i} : date « {v} » illisible (attendu AAAA-MM-JJ), règle sans expiration':
      'line {i}: unreadable date "{v}" (expected YYYY-MM-DD), rule has no expiry',
  'ligne {i} ({id}) : aucune justification (reason=)':
      'line {i} ({id}): no justification (reason=)',
  'référence invalide : tableau "findings" absent (produire le fichier avec `scan --format json`)':
      'invalid baseline: "findings" array missing (produce the file with `scan --format json`)',
  'SBOM de chaque couche scanné séparément : une CVE est comptée dans chaque couche qui apporte le paquet vulnérable, y compris une version remplacée plus haut dans la pile':
      'each layer SBOM scanned separately: a CVE is counted in every layer that brings the vulnerable package, including a version replaced higher in the stack',
  'un seul scan du SBOM global, chaque CVE rattachée à la couche qui a introduit son paquet (CVE de l\'image finale uniquement)':
      'a single scan of the global SBOM, each CVE attached to the layer that introduced its package (final-image CVEs only)',
  'Grype ne voit aucun correctif pour la distribution installée (« won\'t fix » / « non corrigé »). {who} annonce une version corrigée ({versTxt}) : pour un avis de distribution, il s\'agit en général du correctif porté dans les branches *unstable* / *testing*, pas d\'une mise à jour disponible pour la release stable en place.':
      'Grype sees no fix for the installed distribution ("won\'t fix" / "not fixed"). {who} reports a fixed version ({versTxt}): for a distribution advisory, this is usually the fix carried in the *unstable* / *testing* branches, not an update available for the stable release in place.',
  '{pocCount} dépôt(s)': '{pocCount} repo(s)',
  '# Rapport de synthèse — vulnérabilités du SBOM':
      '# Summary report — SBOM vulnerabilities',
  '- **SBOM analysé :** `{sbomPath}`': '- **Analysed SBOM:** `{sbomPath}`',
  '- **Généré le :** {_timestamp}': '- **Generated on:** {_timestamp}',
  '## Résumé global': '## Global summary',
  'Scanners exécutés': 'Scanners run',
  'CVE uniques (tous scanners)': 'Unique CVEs (all scanners)',
  'Résultats bruts cumulés': 'Cumulated raw results',
  'CVE activement exploitées (CISA KEV)': 'Actively exploited CVEs (CISA KEV)',
  'CVE avec EPSS ≥': 'CVEs with EPSS ≥',
  'CVE avec PoC / exploit public': 'CVEs with a public PoC / exploit',
  '## Outils': '## Tools',
  '| Outil | Version |': '| Tool | Version |',
  '## Répartition par scanner': '## Breakdown by scanner',
  '_Non exécuté._': '_Not run._',
  'Aucune vulnérabilité détectée.': 'No vulnerability detected.',
  '| Sévérité | Nombre |': '| Severity | Count |',
  'Autre': 'Other',
  '## Couches de l\'image': '## Image layers',
  'Méthode': 'Method',
  '| Couche | Digest | Instruction | CVE | Critiques | Élevées |':
      '| Layer | Digest | Instruction | CVE | Critical | High |',
  '## Comparaison inter-scanners': '## Cross-scanner comparison',
  '_Aucune CVE détectée par les scanners exécutés._':
      '_No CVE detected by the scanners that ran._',
  'Sévérité': 'Severity',
  'Couche(s)': 'Layer(s)',
  '> Des comptages très différents entre scanners sur les paquets système (Debian/Alpine/RPM) ne signalent pas forcément une erreur : OSV-Scanner en mode « scan de SBOM » peut ne trouver aucune CVE sur ces paquets, et Grype/Trivy n\'ont pas la même exhaustivité sur les avis distro. Voir la documentation, section « Pourquoi Grype, OSV-Scanner et Trivy ne trouvent pas les mêmes CVE ».':
      '> Very different counts between scanners on system packages (Debian/Alpine/RPM) do not necessarily indicate an error: OSV-Scanner in "SBOM scan" mode may find no CVE on these packages, and Grype/Trivy are not equally exhaustive on distro advisories. See the documentation, section "Why Grype, OSV-Scanner and Trivy do not find the same CVEs".',
  '### Notes par CVE': '### Notes per CVE',
  '## Exploitabilité et exploitation active':
      '## Exploitability and active exploitation',
  '### CVE activement exploitées (CISA KEV)':
      '### Actively exploited CVEs (CISA KEV)',
  '| CVE / ID | Paquet | Ajout KEV | Échéance | Rançongiciel |':
      '| CVE / ID | Package | KEV added | Due date | Ransomware |',
  '### Priorisation par risque': '### Risk prioritisation',
  '_Aucune CVE avec signal d\'exploitation notable (CISA KEV, PoC public, ou EPSS ≥ {round} %)._':
      '_No CVE with a notable exploitation signal (CISA KEV, public PoC, or EPSS ≥ {round} %)._',
  'CVE avec un signal d\'exploitation notable, ordonnées par : KEV, puis probabilité EPSS, puis sévérité.':
      'CVEs with a notable exploitation signal, ordered by: KEV, then EPSS probability, then severity.',
  '| CVE / ID | Sévérité | Paquet | KEV | EPSS | Exploitabilité CVSS | PoC public |':
      '| CVE / ID | Severity | Package | KEV | EPSS | CVSS exploitability | Public PoC |',
  '> {_riskRowsOmitted} autre(s) CVE sans signal d\'exploitation notable ne sont pas listées ici (voir la matrice ci-dessus).':
      '> {_riskRowsOmitted} other CVE(s) with no notable exploitation signal are not listed here (see the matrix above).',
  '> **KEV** : CVE au catalogue CISA Known Exploited Vulnerabilities — exploitation active confirmée. **EPSS** : probabilité d\'exploitation dans les 30 jours (score et percentile, FIRST.org). **Exploitabilité CVSS** : sous-score AV/AC/PR/UI (0–3,9) et maturité de l\'exploit quand elle est publiée. **PoC public** : dépôt(s) d\'exploit recensé(s).':
      '> **KEV**: CVE in the CISA Known Exploited Vulnerabilities catalog — confirmed active exploitation. **EPSS**: probability of exploitation within 30 days (score and percentile, FIRST.org). **CVSS exploitability**: AV/AC/PR/UI sub-score (0–3.9) and exploit maturity when published. **Public PoC**: recorded exploit repository(ies).',
  '_Généré par sbom-generator._': '_Generated by sbom-generator._',
  '## Remédiation': '## Remediation',
  '| Paquet | Mise à jour | CVE corrigées | dont KEV | Restantes | Gain |':
      '| Package | Update | CVEs fixed | of which KEV | Remaining | Gain |',
  '## Tendance': '## Trend',
  '- **Nouvelles :** {added}\n- **Disparues :** {removed}\n- **Inchangées :** {unchanged}\n- **Total :** {beforeTotal} → {afterTotal}':
      '- **New:** {added}\n- **Gone:** {removed}\n- **Unchanged:** {unchanged}\n- **Total:** {beforeTotal} → {afterTotal}',
  'nouvelle': 'new',
  '| CVE | Produits | État | Justification |':
      '| CVE | Products | Status | Justification |',
  'tous': 'all',
  '{vexSuppressed} CVE écartée(s) du rapport.':
      '{vexSuppressed} CVE(s) dropped from the report.',
  '## Détail des CVE': '## CVE details',
  'Signalé par': 'Reported by',
  '= Rapport de vulnérabilités: Synthèse inter-scanners':
      '= Vulnerability report: Cross-scanner summary',
  '*Cibles analysées*': '*Analysed targets*',
  '*Cible analysée*': '*Analysed target*',
  '*Scanners exécutés*': '*Scanners run*',
  'NOTE: {vexSuppressed} CVE écartée(s) par une déclaration VEX (voir la section « VEX »).':
      'NOTE: {vexSuppressed} CVE(s) dropped by a VEX statement (see the "VEX" section).',
  'h| Critiques h| Élevées h| CISA KEV h| EPSS >= ':
      'h| Critical h| High h| CISA KEV h| EPSS >= ',
  '== Outils': '== Tools',
  '| Outil | Version': '| Tool | Version',
  '== Répartition par scanner': '== Breakdown by scanner',
  '| Sévérité | Nombre': '| Severity | Count',
  '== Couches de l\'image': '== Image layers',
  '| Couche | Digest | Instruction | CVE | Critiques | Élevées':
      '| Layer | Digest | Instruction | CVE | Critical | High',
  '== Comparaison inter-scanners': '== Cross-scanner comparison',
  '| Sévérité | CVE / ID | Grype | OSV | Trivy':
      '| Severity | CVE / ID | Grype | OSV | Trivy',
  'Des comptages très différents entre scanners sur les paquets système (Debian/Alpine/RPM) ne signalent pas forcément une erreur. OSV-Scanner en mode « scan de SBOM » peut ne trouver aucune CVE sur ces paquets (son API n\'indexe les avis distro que sous une forme de purl absente du SBOM standard). Grype et Trivy n\'ont par ailleurs pas la même exhaustivité sur ces mêmes paquets : Grype reprend l\'intégralité du Debian Security Tracker (avis « won\'t fix » inclus) là où Trivy ne remonte qu\'un sous-ensemble. Voir la documentation utilisateur, section « Pourquoi Grype, OSV-Scanner et Trivy ne trouvent pas les mêmes CVE ».':
      'Very different counts between scanners on system packages (Debian/Alpine/RPM) do not necessarily indicate an error. OSV-Scanner in "SBOM scan" mode may find no CVE on these packages (its API only indexes distro advisories under a purl form absent from the standard SBOM). Grype and Trivy are also not equally exhaustive on these same packages: Grype takes the whole Debian Security Tracker ("won\'t fix" advisories included) where Trivy only reports a subset. See the user documentation, section "Why Grype, OSV-Scanner and Trivy do not find the same CVEs".',
  '=== Notes par CVE': '=== Notes per CVE',
  '== Exploitabilité et exploitation active':
      '== Exploitability and active exploitation',
  '=== CVE activement exploitées (CISA KEV)':
      '=== Actively exploited CVEs (CISA KEV)',
  '| CVE / ID | Paquet | Ajout KEV | Échéance | Rançongiciel':
      '| CVE / ID | Package | KEV added | Due date | Ransomware',
  '=== Priorisation par risque': '=== Risk prioritisation',
  '_Aucune CVE avec signal d\'exploitation notable (CISA KEV, PoC public, ou EPSS >= {round} %)._':
      '_No CVE with a notable exploitation signal (CISA KEV, public PoC, or EPSS >= {round} %)._',
  '| CVE / ID | Sévérité | Paquet | KEV | EPSS ':
      '| CVE / ID | Severity | Package | KEV | EPSS ',
  '| Exploit. CVSS | PoC': '| CVSS exploit. | PoC',
  'NOTE: {_riskRowsOmitted} autre(s) CVE sans signal d\'exploitation notable ne sont pas listées ici (voir la matrice ci-dessus).':
      'NOTE: {_riskRowsOmitted} other CVE(s) with no notable exploitation signal are not listed here (see the matrix above).',
  '*KEV* : CVE au catalogue CISA Known Exploited Vulnerabilities — exploitation active confirmée. *EPSS* : probabilité d\'exploitation dans les 30 jours (score et percentile, FIRST.org). *Exploitabilité CVSS* : sous-score AV/AC/PR/UI (0–3,9) et maturité de l\'exploit quand elle est publiée. *PoC public* : dépôt(s) d\'exploit recensé(s).':
      '*KEV*: CVE in the CISA Known Exploited Vulnerabilities catalog — confirmed active exploitation. *EPSS*: probability of exploitation within 30 days (score and percentile, FIRST.org). *CVSS exploitability*: AV/AC/PR/UI sub-score (0–3.9) and exploit maturity when published. *Public PoC*: recorded exploit repository(ies).',
  '== Remédiation': '== Remediation',
  'Par paquet, la mise à jour minimale qui corrige toutes les CVE corrigeables, classée par *gain de risque* (sévérité, exploitation active KEV, probabilité EPSS).':
      'Per package, the minimal update that fixes every fixable CVE, ranked by *risk reduction* (severity, active exploitation KEV, EPSS probability).',
  '| Paquet | Mise à jour | CVE corrigées | dont KEV | Restantes | Gain':
      '| Package | Update | CVEs fixed | of which KEV | Remaining | Gain',
  'NOTE: {_remediationRows} autre(s) paquet(s) à mettre à jour ne sont pas listés (gain plus faible).':
      'NOTE: {_remediationRows} other package(s) to update are not listed (lower gain).',
  'NOTE: {noFix} paquet(s) n\'ont aucun correctif connu.':
      'NOTE: {noFix} package(s) have no known fix.',
  '_La version cible est une heuristique (comparaison numérique des versions) : à vérifier avec le gestionnaire de paquets._':
      '_The target version is a heuristic (numeric version comparison): check it with the package manager._',
  '== Tendance': '== Trend',
  'h| Nouvelles h| Disparues h| Inchangées h| Total':
      'h| New h| Gone h| Unchanged h| Total',
  '| Sévérité | CVE (paquet)': '| Severity | CVE (package)',
  'NOTE: {rows} autre(s) non listée(s).': 'NOTE: {rows} more not listed.',
  'Nouvelles CVE': 'New CVEs',
  'CVE disparues (corrigées ou plus détectées)':
      'Gone CVEs (fixed or no longer detected)',
  'non affectée': 'not affected',
  'affectée': 'affected',
  'corrigée': 'fixed',
  'à l\'étude': 'under investigation',
  '{vexStatements} déclaration(s) VEX appliquée(s) : {vexSuppressed} CVE écartée(s) du rapport.':
      '{vexStatements} VEX statement(s) applied: {vexSuppressed} CVE(s) dropped from the report.',
  '| CVE | Produits | État | Justification / explication':
      '| CVE | Products | Status | Justification / explanation',
  'CVE écartées': 'Dropped CVEs',
  '== Détail des CVE': '== CVE details',
  'Fiche de chacune des {rows} CVE du rapport.':
      'Detail of each of the {rows} CVEs in the report.',
  'Fiche des {rows} CVE retenues (sévérité {_thresholdLabel} ou CISA KEV).':
      'Detail of the {rows} retained CVEs ({_thresholdLabel} severity or CISA KEV).',
  '{scanner} : publiée {published}, modifiée {modified}':
      '{scanner}: published {published}, modified {modified}',
  'Dates': 'Dates',
  'PoC public': 'Public PoC',
  'Références': 'References',
  'CRITIQUE': 'CRITICAL',
  'ÉLEVÉE': 'HIGH',
  'MOYENNE': 'MEDIUM',
  'FAIBLE': 'LOW',
  'NÉGLIGEABLE': 'NEGLIGIBLE',
  'Action prioritaire. {crit} vulnérabilité(s) critique(s) à corriger en priorité.':
      'Priority action. {crit} critical vulnerability(ies) to fix first.',
  'À traiter. {high} vulnérabilité(s) de sévérité élevée identifiée(s).':
      'To address. {high} high-severity vulnerability(ies) identified.',
  'Aucune vulnérabilité critique ni élevée détectée par les scanners exécutés.':
      'No critical or high vulnerability detected by the scanners that ran.',
  'Répartition par sévérité': 'Severity breakdown',
  '… (liste tronquée à {max} erreurs)': '… (list truncated to {max} errors)',
  'lecture impossible de l\'archive "{path}"': 'cannot read archive "{path}"',
  'sortie inattendue de python3 pour "{path}"':
      'unexpected output from python3 for "{path}"',
  'métadonnées vides pour "{path}"': 'empty metadata for "{path}"',
  'échec de l\'extraction pour "{path}"': 'extraction failed for "{path}"',
  'document VEX non reconnu (attendu : OpenVEX, CSAF VEX ou CycloneDX avec "vulnerabilities")':
      'unrecognised VEX document (expected: OpenVEX, CSAF VEX or CycloneDX with "vulnerabilities")',
  'Voir les correctifs de l\'éditeur.': 'See the vendor fixes.',
  'lecture impossible de la wheel "{path}"': 'cannot read wheel "{path}"',
  'METADATA vide pour "{path}"': 'empty METADATA for "{path}"',
  'aucun Name dans METADATA pour "{path}"': 'no Name in METADATA for "{path}"',
  'yarn.lock introuvable : {path}': 'yarn.lock not found: {path}',
  'Erreur d\'argument : {message}': 'Argument error: {message}',
  '--layer-mode metadata nécessite --oci-tool {tools} ({ociTool} n\'indique pas la couche d\'origine des paquets) — utiliser --layer-mode rootfs.':
      '--layer-mode metadata requires --oci-tool {tools} ({ociTool} does not report the originating layer of packages) — use --layer-mode rootfs.',
  ' ou ': ' or ',
  'Interrogation de {count} paquet(s) — concurrence : {con}{manifests}…':
      'Querying {count} package(s) — concurrency: {con}{manifests}…',
  ' (+ {n} depuis les manifestes)': ' (+ {n} from manifests)',
  'Génération du SBOM de {packageRef}{depth}…':
      'Generating the SBOM of {packageRef}{depth}…',
  ' (profondeur {d})': ' (depth {d})',
  'max': 'max',
  'Mettre à jour vers {versions}.': 'Upgrade to {versions}.',
  'Paquet vulnérable : {pkg} (sévérité {severity}){layer}':
      'Vulnerable package: {pkg} ({severity} severity){layer}',
  ' — couche {layer}': ' — layer {layer}',
  'fichier --baseline introuvable : {path}':
      '--baseline file not found: {path}',
  '--baseline : {message}': '--baseline: {message}',
  '--cache-ttl attend un nombre d\'heures entier ≥ 0.':
      '--cache-ttl expects a whole number of hours ≥ 0.',
  'NOTE: rapport limité aux CVE de sévérité *{threshold}* (ou présentes au catalogue CISA KEV) : {count} {before}CVE uniques.':
      'NOTE: report limited to CVEs of *{threshold}* severity (or listed in the CISA KEV catalog): {count} {before}unique CVEs.',
  'sur {n} ': 'of {n} ',
  'Évolution depuis le rapport de référence{since}.':
      'Change since the reference report{since}.',
  ' du {since}': ' of {since}',
  'Oui — ajoutée le {added}{due}{ransomware}':
      'Yes — added on {added}{due}{ransomware}',
  ', échéance {date}': ', due {date}',
  ', utilisée par des rançongiciels': ', used by ransomware',
  'Action immédiate requise. {kev} CVE du catalogue CISA KEV sont exploitées activement dans la nature — appliquer les correctifs sans délai.':
      'Immediate action required. {kev} CVEs from the CISA KEV catalog are actively exploited in the wild — apply the fixes without delay.',
  'Action immédiate requise. {kev} CVE du catalogue CISA KEV est exploitée activement dans la nature — appliquer les correctifs sans délai.':
      'Immediate action required. {kev} CVE from the CISA KEV catalog is actively exploited in the wild — apply the fixes without delay.',
  '*{count}* CVE uniques': '*{count}* unique CVEs',
  'au moins un --subject est requis.': 'at least one --subject is required.',
  'sujet introuvable : {path}': 'subject not found: {path}',
  'deux sujets portent le même nom : {name}':
      'two subjects have the same name: {name}',
  'ligne {n} ignorée (clé: valeur attendu)':
      'line {n} ignored (key: value expected)',
  'ligne {n} : unknown doit valoir fail, warn ou allow':
      'line {n}: unknown must be fail, warn or allow',
  'ligne {n} : date illisible': 'line {n}: unreadable date',
  'ligne {n} : clé inconnue « {key} »': 'line {n}: unknown key "{key}"',
  'licence inconnue': 'unknown license',
  'licence refusée : {id}': 'denied license: {id}',
  'licence hors liste autorisée : {id}':
      'license not in the allowed list: {id}',
  'Qualité du SBOM : {score}/100 (note {grade})':
      'SBOM quality: {score}/100 (grade {grade})',
  'manquant sur : {list}': 'missing on: {list}',
  'Document VEX (OpenVEX, CSAF ou CycloneDX VEX) : les CVE déclarées\n"not_affected" ou "fixed" pour le paquet concerné sont\nécartées des résultats (et comptées). Répétable : les documents\nsont fusionnés et, en cas de contradiction, la déclaration la plus\nprudente (affected) l\'emporte.':
      'VEX document (OpenVEX, CSAF or CycloneDX VEX): CVEs declared\n"not_affected" or "fixed" for the package concerned are\nremoved from the results (and counted). Repeatable: documents\nare merged and, if they contradict each other, the most\ncautious statement (affected) wins.',
  'Document VEX supplémentaire (OpenVEX / CSAF / CycloneDX), répétable :\nles CVE « non affectées » / « corrigées » sont écartées du rapport.':
      'Additional VEX document (OpenVEX / CSAF / CycloneDX), repeatable:\n"not affected" / "fixed" CVEs are dropped from the report.',
  'Fichier de politique de licences (allow / deny / unknown / except).\nCode retour 2 si au moins un composant la viole.':
      'License policy file (allow / deny / unknown / except).\nExit code 2 if at least one component violates it.',
  'licenses: fichier --policy introuvable : {policyPath}':
      'licenses: --policy file not found: {policyPath}',
  'licenses: exception EXPIRÉE : {package} — non appliquée.':
      'licenses: EXPIRED exception: {package} — not applied.',
  'licenses: avertissement : licence inconnue pour {name}@{version}':
      'licenses: warning: unknown license for {name}@{version}',
  '\n{n} composant(s) violent la politique de licences — code retour 2':
      '\n{n} component(s) violate the license policy — exit code 2',
  'Fichier SBOM (CycloneDX JSON ou SPDX 2.3 JSON).':
      'SBOM file (CycloneDX JSON or SPDX 2.3 JSON).',
  'Artefact attesté (binaire, image exportée, archive…). Son SHA-256\nest calculé. Répétable ; un seul avec --sign.':
      'Attested artifact (binary, exported image, archive…). Its SHA-256\nis computed. Repeatable; only one with --sign.',
  'Contenu attesté :\n  sbom        le SBOM lui-même (défaut)\n  provenance  provenance SLSA v1 (le SBOM est la matière d\'entrée)':
      'Attested content:\n  sbom        the SBOM itself (default)\n  provenance  SLSA v1 provenance (the SBOM is the input material)',
  'Identité du constructeur (URI) — obligatoire avec --predicate provenance.':
      'Builder identity (URI) — required with --predicate provenance.',
  'Type de construction de la provenance (URI).':
      'Provenance build type (URI).',
  'Identifiant de l\'exécution de la construction (ex. numéro de pipeline).':
      'Identifier of the build run (e.g. pipeline number).',
  'Fichier de la déclaration (défaut : <sbom>.intoto.json).':
      'Statement file (default: <sbom>.intoto.json).',
  'Signe la déclaration avec cosign attest-blob (bundle <sortie>.bundle).':
      'Signs the statement with cosign attest-blob (bundle <output>.bundle).',
  'sbom_generator attest – Produit une déclaration in-toto v1 (facultativement\nsignée par cosign) qui lie un SBOM ou une provenance SLSA à des artefacts.\n\nUsage:\n  sbom_generator attest -i sbom.cdx.json -s app.bin\n  sbom_generator attest -i sbom.cdx.json -s app.bin --predicate provenance \\\n      --builder-id https://ci.example/builder --invocation-id 4242\n  sbom_generator attest -i sbom.cdx.json -s app.bin --sign\n\n{usage}\n\nCodes de retour : 0 = succès, 1 = erreur d\'usage ou de signature.\n':
      'sbom_generator attest – Produces an in-toto v1 statement (optionally\nsigned by cosign) that binds an SBOM or a SLSA provenance to artifacts.\n\nUsage:\n  sbom_generator attest -i sbom.cdx.json -s app.bin\n  sbom_generator attest -i sbom.cdx.json -s app.bin --predicate provenance \\\\\n      --builder-id https://ci.example/builder --invocation-id 4242\n  sbom_generator attest -i sbom.cdx.json -s app.bin --sign\n\n{usage}\n\nExit codes: 0 = success, 1 = usage or signing error.\n',
  'fichier introuvable : {inputPath}': 'file not found: {inputPath}',
  '--sign accepte un seul --subject (cosign attest-blob).':
      '--sign accepts a single --subject (cosign attest-blob).',
  '--predicate provenance exige --builder-id.':
      '--predicate provenance requires --builder-id.',
  'impossible de lire le JSON : {e}': 'cannot read the JSON: {e}',
  'format SBOM sans type de prédicat in-toto (SPDX 3.0 ou inconnu) : convertir en CycloneDX ou SPDX 2.3.':
      'SBOM format has no in-toto predicate type (SPDX 3.0 or unknown): convert to CycloneDX or SPDX 2.3.',
  'cosign introuvable — signature impossible.':
      'cosign not found — cannot sign.',
  'cosign a échoué (code {code}) : {err}': 'cosign failed (code {code}): {err}',
  'Fichier SBOM à évaluer (CycloneDX JSON ou SPDX JSON/JSON-LD).':
      'SBOM file to assess (CycloneDX JSON or SPDX JSON/JSON-LD).',
  'Format de sortie.': 'Output format.',
  'Fichier de sortie (défaut : sortie standard).':
      'Output file (default: standard output).',
  'Note minimale (0-100). Code retour 2 si la note est inférieure.':
      'Minimum score (0-100). Exit code 2 if the score is lower.',
  'sbom_generator quality – Note de qualité d\'un SBOM (0-100).\n\nLa note combine les 7 éléments minimaux NTIA (70 %) et la présence des\nempreintes et des licences (30 %). Les composants qui manquent un critère\nsont listés.\n\nUsage:\n  sbom_generator quality -i sbom.cdx.json\n  sbom_generator quality -i sbom.cdx.json --min-score 80 -f json\n\n{usage}\n\nCodes de retour : 0 = succès, 2 = note inférieure à --min-score.\n':
      'sbom_generator quality – Quality score of an SBOM (0-100).\n\nThe score combines the 7 NTIA minimum elements (70%) and the presence of\nhashes and licenses (30%). Components missing a criterion are listed.\n\nUsage:\n  sbom_generator quality -i sbom.cdx.json\n  sbom_generator quality -i sbom.cdx.json --min-score 80 -f json\n\n{usage}\n\nExit codes: 0 = success, 2 = score lower than --min-score.\n',
  'quality: --min-score attend un entier entre 0 et 100.':
      'quality: --min-score expects an integer between 0 and 100.',
  'quality: fichier introuvable : {inputPath}':
      'quality: file not found: {inputPath}',
  'quality: impossible de lire le JSON : {e}':
      'quality: cannot read the JSON: {e}',
  'quality: format SBOM non reconnu dans {inputPath}':
      'quality: SBOM format not recognised in {inputPath}',
  'quality: note {score} inférieure au minimum {min} — code retour 2':
      'quality: score {score} is below the minimum {min} — exit code 2',
  'Document VEX (OpenVEX / CSAF / CycloneDX), répétable : les CVE\n"not_affected" ou "fixed" sont écartées de l\'inventaire des\nvulnérabilités.':
      'VEX document (OpenVEX / CSAF / CycloneDX), repeatable: "not_affected" or\n"fixed" CVEs are removed from the vulnerability inventory.',
};
