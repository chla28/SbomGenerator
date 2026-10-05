import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:args/args.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/deb_parser.dart';
import 'package:sbom_generator/requirements_parser.dart';
import 'package:sbom_generator/rpm_parser.dart';
import 'package:sbom_generator/tar_parser.dart';
import 'package:sbom_generator/wheel_parser.dart';
import 'package:sbom_generator/zip_parser.dart';
import 'package:sbom_generator/jar_parser.dart';
import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/spdx_generator.dart';
import 'package:sbom_generator/spdx3_generator.dart';
import 'package:sbom_generator/simple_json_generator.dart';
import 'package:sbom_generator/markdown_generator.dart';
import 'package:sbom_generator/asciidoc_generator.dart';
import 'package:sbom_generator/html_generator.dart';
import 'package:sbom_generator/oci_parser.dart';
import 'package:sbom_generator/nested_archive.dart';
import 'package:sbom_generator/image_layers.dart';
import 'package:sbom_generator/layer_scan.dart';
import 'package:sbom_generator/sbom_diff.dart';
import 'package:sbom_generator/sbom_merger.dart';
import 'package:sbom_generator/policy_checker.dart';
import 'package:sbom_generator/go_parser.dart';
import 'package:sbom_generator/npm_parser.dart';
import 'package:sbom_generator/yarn_parser.dart';
import 'package:sbom_generator/maven_parser.dart';
import 'package:sbom_generator/pubspec_parser.dart';
import 'package:sbom_generator/csv_generator.dart';
import 'package:sbom_generator/sbom_reader.dart';
import 'package:sbom_generator/scan_report_generator.dart';
import 'package:sbom_generator/license_report_generator.dart';
import 'package:sbom_generator/vuln_enrichment.dart';
import 'package:sbom_generator/cra_report.dart';
import 'package:sbom_generator/i18n.dart';

const _version = '1.6.2';

const _validFormats = {
  'cyclonedx',
  'spdx',
  'spdx3',
  'json',
  'markdown',
  'asciidoc',
  'html',
  'csv'
};
const _validScanners = {'grype', 'osv', 'trivy', 'all'};
const _validOciTools = {'syft', 'trivy', 'skopeo', 'cdxgen'};
const _validDateFields = {'published', 'modified', 'latest'};
const _validScanFormats = {'text', 'sarif', 'markdown', 'asciidoc', 'pdf'};
// Formats produisant un rapport de synthèse inter-scanners (fichier).
const _reportScanFormats = {'markdown', 'asciidoc', 'pdf'};
const _validCycloneDxVersions = CycloneDxGenerator.supportedSpecVersions;
const _validTlpClassifications = CycloneDxGenerator.validTlpClassifications;

Future<void> main(List<String> rawArguments) async {
  final arguments = initLang(rawArguments);
  // Sous-commande `scan` : analyse CVE avec filtre date
  if (arguments.isNotEmpty && arguments.first == 'scan') {
    await _runScan(arguments.sublist(1));
    return;
  }

  // Sous-commande `diff` : compare deux fichiers SBOM
  if (arguments.isNotEmpty && arguments.first == 'diff') {
    await _runDiff(arguments.sublist(1));
    return;
  }

  // Sous-commande `merge` : fusionne plusieurs fichiers SBOM
  if (arguments.isNotEmpty && arguments.first == 'merge') {
    await _runMerge(arguments.sublist(1));
    return;
  }

  // Sous-commande `convert` : convertit entre formats SBOM
  if (arguments.isNotEmpty && arguments.first == 'convert') {
    await _runConvert(arguments.sublist(1));
    return;
  }

  // Sous-commande `validate` : valide la structure d'un fichier SBOM
  if (arguments.isNotEmpty && arguments.first == 'validate') {
    await _runValidate(arguments.sublist(1));
    return;
  }

  // Sous-commande `licenses` : génère un rapport de licences AsciiDoc
  if (arguments.isNotEmpty && arguments.first == 'licenses') {
    await _runLicenses(arguments.sublist(1));
    return;
  }

  // Sous-commande `cra` : rapport de conformité Cyber Resilience Act
  if (arguments.isNotEmpty && arguments.first == 'cra') {
    await _runCra(arguments.sublist(1));
    return;
  }

  final parser = ArgParser()
    ..addOption(
      'input',
      abbr: 'i',
      help: tr(
        'Fichier d\'entrée contenant une référence de paquet par ligne, un\n'
            'fichier archive/paquet unique, ou un dossier à parcourir\n'
            'récursivement. Chaque ligne (ou fichier découvert) peut être :\n'
            '  • un nom de paquet RPM, un NEVRA ou un chemin vers un .rpm\n'
            '  • un chemin vers un paquet Debian .deb\n'
            '  • un chemin vers une wheel Python .whl\n'
            '  • un chemin vers un fichier requirements.txt\n'
            '  • un chemin vers une archive .tar / .tar.gz / .tgz / .zip\n'
            '  • un chemin vers un .jar (coordonnées Maven via\n'
            '    META-INF/maven/*/*/pom.properties, ou convention de nom)\n'
            '  • un chemin vers un fichier go.sum ou go.mod\n'
            '  • un chemin vers un package-lock.json ou un yarn.lock\n'
            '  • un chemin vers un fichier pom.xml\n'
            '  • un chemin vers un pubspec.lock ou un pubspec.yaml\n'
            'Si --input est un dossier, tous les types de fichiers ci-dessus\n'
            'y sont recherchés récursivement (unzip requis pour les .jar).\n'
            'Facultatif si --image est fourni.',
        'Input file containing one package reference per line, a single\n'
            'archive/package file, or a directory to scan recursively.\n'
            'Each line (or discovered file) may be:\n'
            '  • an RPM package name, NEVRA, or path to a .rpm file\n'
            '  • a path to a Debian .deb file\n'
            '  • a path to a Python .whl file\n'
            '  • a path to a requirements.txt file\n'
            '  • a path to a .tar / .tar.gz / .tgz / .zip archive\n'
            '  • a path to a .jar file (Maven coordinates via\n'
            '    META-INF/maven/*/*/pom.properties, or filename convention)\n'
            '  • a path to a go.sum or go.mod file\n'
            '  • a path to a package-lock.json or yarn.lock file\n'
            '  • a path to a pom.xml file\n'
            '  • a path to a pubspec.lock or pubspec.yaml file\n'
            'If --input is a directory, it is scanned recursively for all of\n'
            'the file types above (requires unzip for .jar).\n'
            'Optional when --image is provided.',
      ),
    )
    ..addOption(
      'image',
      abbr: 'I',
      help: tr(
        'Image de conteneur OCI à analyser.\n'
            'Formats acceptés :\n'
            '  • Registre  : nginx:latest  ubuntu@sha256:…\n'
            '  • Archive   : /chemin/image.tar  (docker save)\n'
            '  • OCI layout: /chemin/vers/oci_dir/  (index.json présent)\n'
            'À combiner avec --oci-tool pour choisir le backend.\n'
            'Un chemin de fichier local (binaire) fonctionne aussi via le\n'
            'backend syft — voir --binary, plus explicite pour ce cas.',
        'OCI container image to analyse.\n'
            'Accepted formats:\n'
            '  • Registry  : nginx:latest  ubuntu@sha256:…\n'
            '  • Archive   : /path/image.tar  (docker save)\n'
            '  • OCI layout: /path/to/oci_dir/  (index.json present)\n'
            'Combine with --oci-tool to choose the backend.\n'
            'A local file path (binary) also works through the syft\n'
            'backend — see --binary, more explicit for that case.',
      ),
    )
    ..addOption(
      'binary',
      abbr: 'b',
      help: tr(
        'Binaire local à analyser directement (ex. exécutable Go lié\n'
            'statiquement) — alias explicite pour --image <fichier>.\n'
            'Force --oci-tool syft : seul backend qui sait exploiter les\n'
            'métadonnées embarquées dans un binaire autonome (buildinfo Go\n'
            'via `go-module-binary-cataloger`, classifieur générique pour\n'
            'quelques bibliothèques connues — OpenSSL, zlib, sqlite…).\n'
            'Ne récupère PAS les dépendances de bibliothèques liées\n'
            'statiquement sans métadonnée embarquée (C/C++ « fait maison »,\n'
            'Rust sans cargo-auditable).',
        'Local binary to analyse directly (e.g. a statically linked Go\n'
            'executable) — explicit alias for --image <file>.\n'
            'Forces --oci-tool syft: the only backend able to use the\n'
            'metadata embedded in a standalone binary (Go buildinfo via\n'
            '`go-module-binary-cataloger`, generic classifier for a few\n'
            'well-known libraries — OpenSSL, zlib, sqlite…).\n'
            'Does NOT recover the dependencies of statically linked\n'
            'libraries lacking embedded metadata (home-grown C/C++,\n'
            'Rust without cargo-auditable).',
      ),
    )
    ..addOption(
      'oci-tool',
      defaultsTo: 'syft',
      help: tr(
        'Backend d\'analyse OCI (utilisé avec --image).\n'
            '  syft    Anchore Syft (défaut) — tous types de paquets\n'
            '  trivy   Aqua Trivy — tous types de paquets\n'
            '  skopeo  Skopeo + extraction manuelle (dpkg/rpm/apk)\n'
            '  cdxgen  OWASP cdxgen — tous types de paquets',
        'OCI analysis backend (used with --image).\n'
            '  syft    Anchore Syft (default) — all package types\n'
            '  trivy   Aqua Trivy — all package types\n'
            '  skopeo  Skopeo + manual extraction (dpkg/rpm/apk)\n'
            '  cdxgen  OWASP cdxgen — all package types',
      ),
    )
    ..addFlag(
      'per-layer',
      negatable: false,
      help: tr(
        'Avec --image : génère en plus un SBOM par couche de l\'image\n'
            '(delta de la couche : composants ajoutés/modifiés, supprimés\n'
            'listés à part), dans chaque format demandé, à côté de -o :\n'
            '<base>.layer-NN-<digest12>.<ext>. Le SBOM global indique la\n'
            'couche d\'origine de chaque composant.',
        'With --image: also generates one SBOM per image layer (layer\n'
            'delta: added/modified components, removed ones listed\n'
            'separately), in each requested format, next to -o:\n'
            '<base>.layer-NN-<digest12>.<ext>. The global SBOM states the\n'
            'originating layer of each component.',
      ),
    )
    ..addOption(
      'layer-mode',
      allowed: validLayerModes,
      help: tr(
        'Méthode de calcul de --per-layer :\n'
            '  metadata  couche d\'origine indiquée par le backend (défaut ;\n'
            '            syft et trivy uniquement) — rapide, ajouts seulement\n'
            '  rootfs    couches appliquées une à une et rootfs réanalysé\n'
            '            après chacune — ajouts, modifications, suppressions\n'
            '            (défaut forcé pour skopeo et cdxgen)',
        'Computation method for --per-layer:\n'
            '  metadata  originating layer reported by the backend (default;\n'
            '            syft and trivy only) — fast, additions only\n'
            '  rootfs    layers applied one by one and the rootfs re-analysed\n'
            '            after each — additions, changes, removals\n'
            '            (forced default for skopeo and cdxgen)',
      ),
    )
    ..addOption(
      'depth',
      defaultsTo: '0',
      help: tr(
        'Profondeur de descente dans les objets imbriqués de --input :\n'
            '  0     l\'objet seul (défaut)\n'
            '  N     N niveaux (1 = jars/paquets/archives contenus dans un\n'
            '        rpm, deb, tar, zip, jar/war/ear, wheel ; 2 = ce que\n'
            '        contiennent ces derniers…)\n'
            '  all   sans limite (plafonné à $maxNestedDepth niveaux)\n'
            'Les composants trouvés sont ajoutés au SBOM de l\'objet\n'
            '(propriétés location/depth, arêtes de dépendance parent → enfant)\n'
            'et un SBOM par objet imbriqué est écrit à côté de -o\n'
            '(<base>.nested-NN-<objet>.<ext>, voir --no-nested-files).\n'
            'Les manifestes rencontrés (package-lock.json, go.sum, pom.xml…)\n'
            'sont analysés. Extraction bornée (taille, nombre de fichiers).',
        'Depth of descent into the nested objects of --input:\n'
            '  0     the object alone (default)\n'
            '  N     N levels (1 = jars/packages/archives contained in an\n'
            '        rpm, deb, tar, zip, jar/war/ear, wheel; 2 = what those\n'
            '        contain…)\n'
            '  all   unlimited (capped at $maxNestedDepth levels)\n'
            'Components found are added to the object\'s SBOM\n'
            '(location/depth properties, parent → child dependency edges)\n'
            'and one SBOM per nested object is written next to -o\n'
            '(<base>.nested-NN-<object>.<ext>, see --no-nested-files).\n'
            'Manifests encountered (package-lock.json, go.sum, pom.xml…)\n'
            'are analysed. Extraction is bounded (size, number of files).',
      ),
    )
    ..addFlag(
      'nested-files',
      defaultsTo: true,
      help: tr(
        'Avec --depth : écrire un SBOM par objet imbriqué en plus du SBOM\n'
            'fusionné. --no-nested-files : fusionné seulement.',
        'With --depth: write one SBOM per nested object in addition to the\n'
            'merged SBOM. --no-nested-files: merged one only.',
      ),
    )
    ..addOption(
      'output',
      abbr: 'o',
      defaultsTo: 'sbom.json',
      help: tr(
        'Chemin du fichier de sortie.\n'
            'Format unique : utilisé tel quel.\n'
            'Plusieurs formats (-f a,b) : utilisé comme base ; les extensions\n'
            'propres à chaque format sont ajoutées (.cdx.json, .spdx.json,\n'
            '.spdx3.jsonld, …).',
        'Output file path.\n'
            'Single format: used as-is.\n'
            'Multiple formats (-f a,b): used as a base path; format-specific\n'
            'extensions are appended (.cdx.json, .spdx.json, .spdx3.jsonld, …).',
      ),
    )
    ..addOption(
      'format',
      abbr: 'f',
      defaultsTo: 'cyclonedx',
      help: tr(
        'Format(s) de sortie, séparés par des virgules.\n'
            '  cyclonedx  CycloneDX 1.6 ou 1.7 JSON (défaut : 1.6, voir --cyclonedx-version)\n'
            '  spdx       SPDX 2.3 JSON\n'
            '  spdx3      SPDX 3.0 JSON-LD\n'
            '  json       JSON lisible personnalisé\n'
            '  markdown   Tableau Markdown des licences\n'
            '  asciidoc   Tableau AsciiDoc des licences\n'
            '  html       Rapport HTML interactif (tableau filtrable)\n'
            '  csv        Fichier CSV (une ligne par paquet)\n'
            'Exemple : -f cyclonedx,spdx,csv',
        'Output format(s), comma-separated.\n'
            '  cyclonedx  CycloneDX 1.6 or 1.7 JSON (default: 1.6, see --cyclonedx-version)\n'
            '  spdx       SPDX 2.3 JSON\n'
            '  spdx3      SPDX 3.0 JSON-LD\n'
            '  json       Custom human-friendly JSON\n'
            '  markdown   Markdown licence table\n'
            '  asciidoc   AsciiDoc licence table\n'
            '  html       Interactive HTML report (filterable table)\n'
            '  csv        CSV file (one row per package)\n'
            'Example: -f cyclonedx,spdx,csv',
      ),
    )
    ..addOption(
      'name',
      abbr: 'n',
      help: tr('Nom du document SBOM / du composant racine.',
          'Name for the SBOM document / root component.'),
    )
    ..addOption(
      'supplier',
      help: tr(
        'Fournisseur par défaut des composants dont la source ne porte\n'
            'aucune information d\'éditeur (lockfiles npm/yarn/Go/pip/pub,\n'
            'requirements.txt…). N\'écrase jamais un fournisseur déjà détecté\n'
            '(RPM %{VENDOR}, Maintainer Debian, groupId Maven…).\n'
            'Champ obligatoire de BSI TR-03183-2 / éléments minimaux NTIA.',
        'Default supplier for components whose source carries no vendor\n'
            'information (npm/yarn/Go/pip/pub lockfiles, requirements.txt…).\n'
            'Never overrides a supplier that was already detected\n'
            '(RPM %{VENDOR}, Debian Maintainer, Maven groupId…).\n'
            'Mandatory field of BSI TR-03183-2 / NTIA minimum elements.',
      ),
    )
    ..addOption(
      'rpm-dir',
      abbr: 'd',
      help: tr(
        'Dossier où chercher récursivement des fichiers .rpm.\n'
            'Sert à résoudre les noms de paquet nus (sans chemin ni extension)\n'
            'vers des .rpm locaux au lieu d\'interroger la base installée.',
        'Directory to search recursively for .rpm files.\n'
            'Used to resolve bare package names (no path, no extension)\n'
            'to local .rpm files instead of querying the installed database.',
      ),
    )
    ..addFlag(
      'verbose',
      abbr: 'v',
      defaultsTo: false,
      negatable: false,
      help:
          tr('Affiche le détail de la progression.', 'Print progress details.'),
    )
    ..addOption(
      'concurrency',
      abbr: 'c',
      defaultsTo: '4',
      help: tr(
        'Nombre maximal de paquets traités en parallèle.\n'
            '1 = séquentiel. 0 = illimité.',
        'Maximum packages processed concurrently.\n'
            '1 = sequential. 0 = unlimited.',
      ),
    )
    ..addOption(
      'license-map',
      abbr: 'l',
      help: tr(
        'Chemin d\'un fichier de substitution de licences.\n'
            'Format : un « nom_de_paquet: expression-SPDX » par ligne.\n'
            'Les lignes commençant par # sont ignorées.\n'
            'Remplace la licence détectée pour les noms de paquet concernés.',
        'Path to a license override file.\n'
            'Format: one "package_name: SPDX-expression" per line.\n'
            'Lines starting with # are ignored.\n'
            'Overrides the detected license for matching package names.',
      ),
    )
    ..addMultiOption(
      'deny-license',
      help: tr(
        'Fait échouer la génération si un paquet a cette licence.\n'
            'Peut être répété. Supporte les expressions SPDX partielles.\n'
            'Exemple : --deny-license GPL-3.0 --deny-license AGPL-3.0',
        'Fails the generation if a package has this license.\n'
            'May be repeated. Supports partial SPDX expressions.\n'
            'Example: --deny-license GPL-3.0 --deny-license AGPL-3.0',
      ),
    )
    ..addMultiOption(
      'sdk-version',
      help: tr(
        'Version réelle d\'un SDK Dart/Flutter, pour les paquets\n'
            '`source: sdk` d\'un pubspec.lock/pubspec.yaml (que le lockfile\n'
            'note toujours 0.0.0). Format <sdk>=<version>, répétable.\n'
            'Exemple : --sdk-version flutter=3.47.2 --sdk-version dart=3.9.0',
        'Actual version of a Dart/Flutter SDK, for the `source: sdk`\n'
            'packages of a pubspec.lock/pubspec.yaml (which the lockfile\n'
            'always records as 0.0.0). Format <sdk>=<version>, repeatable.\n'
            'Example: --sdk-version flutter=3.47.2 --sdk-version dart=3.9.0',
      ),
    )
    ..addOption(
      'pub-cache',
      help: tr(
        'Répertoire du cache pub (contient hosted/<hôte>/<nom>-<version>/).\n'
            'Sert à lire le fichier LICENSE de chaque paquet d\'un pubspec.lock\n'
            '(le lockfile ne contient aucune licence). Par défaut : \$PUB_CACHE,\n'
            'sinon ~/.pub-cache s\'il existe. Passer "" pour désactiver.',
        'Pub cache directory (contains hosted/<host>/<name>-<version>/).\n'
            'Used to read the LICENSE file of each package of a pubspec.lock\n'
            '(the lockfile holds no license). Default: \$PUB_CACHE,\n'
            'otherwise ~/.pub-cache if it exists. Pass "" to disable.',
      ),
    )
    ..addOption(
      'flutter-root',
      help: tr(
        'Racine du SDK Flutter, pour lire le LICENSE des paquets\n'
            '`source: sdk` (flutter, sky_engine…). Par défaut : \$FLUTTER_ROOT.',
        'Flutter SDK root, to read the LICENSE of `source: sdk`\n'
            'packages (flutter, sky_engine…). Default: \$FLUTTER_ROOT.',
      ),
    )
    ..addOption(
      'cyclonedx-version',
      defaultsTo: '1.6',
      allowed: _validCycloneDxVersions,
      help: tr(
        'Version de la spécification CycloneDX à générer.\n'
            '  1.6  (défaut, la plus répandue chez les consommateurs actuels)\n'
            '  1.7  Ajoute citations/patentAssertions/distributionConstraints '
            'quand --tlp ou --patent-map sont fournis.',
        'CycloneDX specification version to generate.\n'
            '  1.6  (default, the most widespread among current consumers)\n'
            '  1.7  Adds citations/patentAssertions/distributionConstraints '
            'when --tlp or --patent-map are provided.',
      ),
    )
    ..addOption(
      'tlp',
      allowed: _validTlpClassifications,
      help: tr(
        'Classification TLP (Traffic Light Protocol) du BOM.\n'
            'Nécessite --cyclonedx-version 1.7.\n'
            'Valeurs : ${_validTlpClassifications.join(", ")}',
        'TLP (Traffic Light Protocol) classification of the BOM.\n'
            'Requires --cyclonedx-version 1.7.\n'
            'Values: ${_validTlpClassifications.join(", ")}',
      ),
    )
    ..addOption(
      'patent-map',
      help: tr(
        'Chemin vers un fichier de déclarations de brevets.\n'
            'Nécessite --cyclonedx-version 1.7.\n'
            'Format : une ligne "nom_de_paquet: numéro|juridiction|statut|type"\n'
            'Exemple : openssl: US1234567|US|granted|license',
        'Path to a patent declarations file.\n'
            'Requires --cyclonedx-version 1.7.\n'
            'Format: one line "package_name: number|jurisdiction|status|type"\n'
            'Example: openssl: US1234567|US|granted|license',
      ),
    )
    ..addOption(
      'min-quality-score',
      help: tr(
        'Score sbomqs minimum (0-10). Échoue si le score est inférieur.\n'
            'Requiert que sbomqs soit installé.',
        'Minimum sbomqs score (0-10). Fails if the score is lower.\n'
            'Requires sbomqs to be installed.',
      ),
    )
    ..addFlag(
      'sign',
      defaultsTo: false,
      negatable: false,
      help: tr(
        'Signe le SBOM généré avec cosign (requiert cosign installé).\n'
            'La clé est lue depuis les variables d\'environnement cosign standard.',
        'Signs the generated SBOM with cosign (requires cosign installed).\n'
            'The key is read from the standard cosign environment variables.',
      ),
    )
    ..addOption(
      'lang',
      allowed: ['fr', 'en'],
      help: tr(
        'Langue des messages (défaut : SBOM_LANG, puis LC_ALL/LANG, sinon fr).',
        'Message language (default: SBOM_LANG, then LC_ALL/LANG, else fr).',
      ),
    )
    ..addFlag(
      'version',
      defaultsTo: false,
      negatable: false,
      help: tr('Affiche la version et quitte.', 'Print version and exit.'),
    )
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: tr('Affiche cette aide.', 'Show this help message.'),
    );

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    _err(tr(
        'Erreur d\'argument : ${e.message}', 'Argument error: ${e.message}'));
    _printUsage(parser);
    exit(1);
  }

  if (args['help'] as bool) {
    _printUsage(parser);
    exit(0);
  }

  if (args['version'] as bool) {
    print('sbom_generator $_version');
    exit(0);
  }

  if (!args.wasParsed('input') &&
      !args.wasParsed('image') &&
      !args.wasParsed('binary')) {
    _err(tr('Au moins une source est requise : --input, --image ou --binary.',
        'At least one source is required: --input, --image or --binary.'));
    _printUsage(parser);
    exit(1);
  }
  if (args.wasParsed('image') && args.wasParsed('binary')) {
    _err(tr(
        '--image et --binary sont exclusifs (le second est un alias '
            'explicite du premier pour un fichier local).',
        '--image and --binary are mutually exclusive (the latter is an '
            'explicit alias of the former for a local file).'));
    exit(1);
  }

  final inputPath = args['input'] as String?;
  final binaryPath = args['binary'] as String?;
  var ociTool = args['oci-tool'] as String;
  if (binaryPath != null) {
    if (!File(binaryPath).existsSync()) {
      _err(tr('--binary : fichier introuvable : $binaryPath',
          '--binary: file not found: $binaryPath'));
      exit(1);
    }
    if (args.wasParsed('oci-tool') && ociTool != 'syft') {
      _err(tr(
          '--binary ne fonctionne qu\'avec --oci-tool syft (seul backend '
              'capable d\'analyser un binaire autonome).',
          '--binary only works with --oci-tool syft (the only backend able '
              'to analyse a standalone binary).'));
      exit(1);
    }
    ociTool = 'syft';
  }
  final imageRef = binaryPath ?? (args['image'] as String?);
  final outputPath = args['output'] as String;
  final docName = args['name'] as String?;
  final verbose = args['verbose'] as bool;
  final rpmDir = args['rpm-dir'] as String?;
  final concurrencyN = () {
    final n = int.tryParse(args['concurrency'] as String) ?? 4;
    if (n < 0) {
      _err(tr('--concurrency doit être ≥ 0.', '--concurrency must be ≥ 0.'));
      exit(1);
    }
    return n;
  }();

  // Parse and validate format list (comma-separated)
  final formats = (args['format'] as String)
      .split(',')
      .map((f) => f.trim())
      .where((f) => f.isNotEmpty)
      .toList();
  if (formats.isEmpty) {
    _err(tr('--format ne doit pas être vide.', '--format must not be empty.'));
    exit(1);
  }
  for (final f in formats) {
    if (!_validFormats.contains(f)) {
      _err(tr('Format inconnu "$f". Valides : ${_validFormats.join(', ')}',
          'Unknown format "$f". Valid: ${_validFormats.join(', ')}'));
      exit(1);
    }
  }

  // Validation --oci-tool
  if (!_validOciTools.contains(ociTool)) {
    _err(tr(
        'Outil OCI inconnu "$ociTool". Valides : ${_validOciTools.join(', ')}',
        'Unknown OCI tool "$ociTool". Valid: ${_validOciTools.join(', ')}'));
    exit(1);
  }

  // Validation --per-layer / --layer-mode
  final perLayer = args['per-layer'] as bool;
  var layerMode = args['layer-mode'] as String?;
  if (layerMode != null && !perLayer) {
    _err(tr('--layer-mode nécessite --per-layer.',
        '--layer-mode requires --per-layer.'));
    exit(1);
  }
  if (perLayer) {
    if (binaryPath != null ||
        imageRef == null ||
        OciParser.detectRefType(imageRef) == OciRefType.binary) {
      _err(tr(
          '--per-layer nécessite une image de conteneur (--image) : un '
              'binaire autonome n\'a pas de couches.',
          '--per-layer requires a container image (--image): a standalone '
              'binary has no layers.'));
      exit(1);
    }
    if (layerMode == 'metadata' && !metadataLayerTools.contains(ociTool)) {
      _err(tr(
          '--layer-mode metadata nécessite --oci-tool '
              '${metadataLayerTools.join(' ou ')} ($ociTool n\'indique pas la '
              'couche d\'origine des paquets) — utiliser --layer-mode rootfs.',
          '--layer-mode metadata requires --oci-tool '
              '${metadataLayerTools.join(' or ')} ($ociTool does not report the '
              'originating layer of packages) — use --layer-mode rootfs.'));
      exit(1);
    }
    if (layerMode == null) {
      layerMode = metadataLayerTools.contains(ociTool) ? 'metadata' : 'rootfs';
      if (layerMode == 'rootfs') {
        print(tr(
            '--per-layer : mode rootfs (seul mode possible avec $ociTool).',
            '--per-layer: rootfs mode (the only possible mode with $ociTool).'));
      }
    }
    // Le mode rootfs copie une image de registre en local via skopeo.
    if (layerMode == 'rootfs' &&
        ociTool != 'skopeo' &&
        OciParser.detectRefType(imageRef) == OciRefType.registry &&
        (await Process.run('skopeo', ['--version'])).exitCode != 0) {
      _err(tr(
          '--layer-mode rootfs sur une image de registre nécessite skopeo '
              '(copie locale des couches).',
          '--layer-mode rootfs on a registry image requires skopeo '
              '(local copy of the layers).'));
      exit(1);
    }
  }

  // Validation --depth
  final nestedDepth = parseNestedDepth(args['depth'] as String);
  if (nestedDepth == null) {
    _err(tr('--depth attend un entier ≥ 0 ou "all" (reçu "${args['depth']}").',
        '--depth expects an integer ≥ 0 or "all" (got "${args['depth']}").'));
    exit(1);
  }
  final nestedFiles = args['nested-files'] as bool;
  if (nestedDepth > 0 && inputPath == null) {
    _err(tr(
        '--depth s\'applique aux objets de --input (rpm, deb, tar, zip, '
            'jar…) ; pour une image, voir --per-layer.',
        '--depth applies to --input objects (rpm, deb, tar, zip, jar…); '
            'for an image, see --per-layer.'));
    exit(1);
  }

  // Load license overrides
  final licenseMapPath = args['license-map'] as String?;
  final licenseOverrides = licenseMapPath != null
      ? _parseLicenseMap(licenseMapPath)
      : <String, String>{};
  final denyLicenses = args['deny-license'] as List<String>;
  final sdkVersions = <String, String>{};
  for (final entry in args['sdk-version'] as List<String>) {
    final eq = entry.indexOf('=');
    if (eq <= 0) {
      _err(tr('--sdk-version attend <sdk>=<version> (reçu "$entry").',
          '--sdk-version expects <sdk>=<version> (got "$entry").'));
      exit(1);
    }
    sdkVersions[entry.substring(0, eq).trim()] = entry.substring(eq + 1).trim();
  }
  // Cache pub / racine Flutter pour lire les licences des paquets pub
  // (le pubspec.lock n'en contient aucune). Auto-détection si non fourni.
  String? pubCacheDir = args['pub-cache'] as String?;
  if (pubCacheDir == null) {
    final env = Platform.environment;
    final candidate = env['PUB_CACHE'] ??
        (env['HOME'] != null ? '${env['HOME']}/.pub-cache' : null);
    if (candidate != null && Directory(candidate).existsSync()) {
      pubCacheDir = candidate;
    }
  } else if (pubCacheDir.isEmpty) {
    pubCacheDir = null; // --pub-cache "" → désactivé explicitement
  }
  final flutterRootDir =
      (args['flutter-root'] as String?) ?? Platform.environment['FLUTTER_ROOT'];
  if (verbose && pubCacheDir != null) {
    print(tr('Cache pub pour les licences : $pubCacheDir',
        'Pub cache for licenses: $pubCacheDir'));
  }

  final minQualityScore = args['min-quality-score'] as String?;
  final signSbom = args['sign'] as bool;
  if (verbose && licenseOverrides.isNotEmpty) {
    print(tr(
        'Substitutions de licence : ${licenseOverrides.length} entrée(s) chargée(s).',
        'License overrides: ${licenseOverrides.length} entr(y/ies) loaded.'));
  }

  // CycloneDX 1.7 : version cible + champs optionnels associés
  final cycloneDxVersion = args['cyclonedx-version'] as String;
  final tlp = args['tlp'] as String?;
  final patentMapPath = args['patent-map'] as String?;
  final patentMap = patentMapPath != null
      ? _parsePatentMap(patentMapPath)
      : <String, PatentAssertion>{};
  if (cycloneDxVersion != '1.7' && (tlp != null || patentMap.isNotEmpty)) {
    _err(tr('--tlp et --patent-map nécessitent --cyclonedx-version 1.7.',
        '--tlp and --patent-map require --cyclonedx-version 1.7.'));
    exit(1);
  }
  // Le BOM ne peut réellement attribuer les données de composants à un outil
  // externe que lorsque celui-ci a effectivement produit la liste (--image).
  final citationSource =
      (cycloneDxVersion == '1.7' && imageRef != null) ? ociTool : null;

  if (inputPath != null) {
    final inputType = await FileSystemEntity.type(inputPath);
    if (inputType == FileSystemEntityType.notFound) {
      _err(
          tr('Entrée introuvable : $inputPath', 'Input not found: $inputPath'));
      exit(1);
    }
  }

  // --- Read package list (optionnel si --image est fourni) ---
  List<String> packageRefs = [];
  if (inputPath != null) {
    if (await FileSystemEntity.isDirectory(inputPath)) {
      // --input pointe vers un dossier : scan récursif de tous les types de
      // paquets/manifestes reconnus (pas de fichier liste dans ce cas).
      final found = <String>[];
      await for (final entity
          in Directory(inputPath).list(recursive: true, followLinks: false)) {
        if (entity is File && _isSupportedPackageFile(entity.path)) {
          found.add(entity.path);
        }
      }
      found.sort();
      // Dans un même dossier, pubspec.lock (versions résolues + fermeture
      // transitive) prime sur pubspec.yaml (contraintes directes seulement).
      final pubspecLockDirs = found
          .where((p) => p.endsWith('/pubspec.lock'))
          .map((p) => p.substring(0, p.length - 'pubspec.lock'.length))
          .toSet();
      found.removeWhere((p) =>
          p.endsWith('/pubspec.yaml') &&
          pubspecLockDirs
              .contains(p.substring(0, p.length - 'pubspec.yaml'.length)));
      packageRefs = found;
      if (verbose) {
        print(tr(
            '${found.length} fichier(s) de paquet trouvé(s) dans $inputPath.',
            '${found.length} package file(s) found in $inputPath.'));
      }
      if (packageRefs.isEmpty && imageRef == null) {
        _err(tr('Aucun paquet reconnu dans le dossier $inputPath.',
            'No recognised package in directory $inputPath.'));
        exit(1);
      }
    } else if (_isSingleArchiveInput(inputPath) ||
        _isSupportedPackageFile(inputPath)) {
      // --input pointe directement vers une archive/un paquet/un manifeste
      // unique (et non vers un fichier liste) : on l'utilise tel quel.
      packageRefs = [inputPath];
    } else {
      List<String> lines;
      try {
        lines = await File(inputPath).readAsLines();
      } on FileSystemException {
        _err(tr(
            '$inputPath ne semble pas être un fichier texte lisible. '
                'Si c\'est une archive (.zip/.tar/.tar.gz/.tgz/.whl/.deb/.rpm/.jar), '
                'passez-la directement via --input, sinon --input doit être un '
                'fichier listant une référence de paquet par ligne, ou un dossier '
                'à scanner.',
            '$inputPath does not look like a readable text file. '
                'If it is an archive (.zip/.tar/.tar.gz/.tgz/.whl/.deb/.rpm/.jar), '
                'pass it directly via --input; otherwise --input must be a '
                'file listing one package reference per line, or a directory '
                'to scan.'));
        exit(1);
      }
      packageRefs = lines
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty && !l.startsWith('#'))
          .toList();

      if (packageRefs.isEmpty && imageRef == null) {
        _err(tr(
            'Aucun paquet trouvé dans $inputPath '
                '(fichier vide ou lignes toutes commentées).',
            'No packages found in $inputPath '
                '(empty file or all lines are comments).'));
        exit(1);
      }
    }
  }

  // --- Build RPM file index from --rpm-dir ---
  final rpmExactIndex = <String, String>{}; // stem (without .rpm) → path
  final rpmNameIndex =
      <String, List<String>>{}; // package name → sorted [paths]
  if (rpmDir != null) {
    final dir = Directory(rpmDir);
    if (!await dir.exists()) {
      _err(tr('Dossier RPM introuvable : $rpmDir',
          'RPM directory not found: $rpmDir'));
      exit(1);
    }
    await for (final entity in dir.list(recursive: true, followLinks: false)) {
      if (entity is File && entity.path.endsWith('.rpm')) {
        final stem =
            entity.path.split('/').last.replaceAll(RegExp(r'\.rpm$'), '');
        rpmExactIndex[stem] = entity.path;
        final name = RegExp(r'^(.+?)-\d').firstMatch(stem)?.group(1) ?? stem;
        rpmNameIndex.putIfAbsent(name, () => []).add(entity.path);
      }
    }
    for (final paths in rpmNameIndex.values) paths.sort();
    if (verbose) {
      print(tr('${rpmExactIndex.length} fichier(s) RPM trouvé(s) dans $rpmDir.',
          'Found ${rpmExactIndex.length} RPM file(s) in $rpmDir.'));
    }
  }

  // --- Expand manifest/lockfiles (preprocess before the main loop) ---
  final reqParser = RequirementsParser();
  final goParser = GoParser();
  final npmParser = NpmParser();
  final yarnParser = YarnParser();
  final mavenParser = MavenParser();
  final pubspecParser = PubspecParser();
  final preloadedPackages = <Package>[];
  final filteredRefs = <String>[];
  for (final ref in packageRefs) {
    if (_isRequirements(ref)) {
      preloadedPackages.addAll(reqParser.parseFile(ref));
    } else if (_isGoSum(ref)) {
      preloadedPackages.addAll(goParser.parseGoSum(ref));
    } else if (_isGoMod(ref)) {
      preloadedPackages.addAll(goParser.parseGoMod(ref));
    } else if (_isPackageLock(ref)) {
      preloadedPackages.addAll(npmParser.parsePackageLock(ref));
    } else if (_isYarnLock(ref)) {
      preloadedPackages.addAll(yarnParser.parseYarnLock(ref));
    } else if (_isPomXml(ref)) {
      preloadedPackages.addAll(mavenParser.parsePomXml(ref));
    } else if (_isPubspecLock(ref)) {
      preloadedPackages.addAll(pubspecParser.parsePubspecLock(ref,
          sdkVersions: sdkVersions,
          pubCache: pubCacheDir,
          flutterRoot: flutterRootDir));
    } else if (_isPubspecYaml(ref)) {
      preloadedPackages.addAll(
          pubspecParser.parsePubspecYaml(ref, sdkVersions: sdkVersions));
    } else {
      filteredRefs.add(ref);
    }
  }
  final mainRefs = filteredRefs;

  // --- Analyse OCI image ---
  final ociPackages = <Package>[];
  OsInfo? ociOs;
  if (imageRef != null) {
    // Vérifier la disponibilité de l'outil OCI
    final ociCheck = await Process.run(ociTool, ['--version']);
    if (ociCheck.exitCode != 0) {
      _err(tr(
          '$ociTool introuvable ou non fonctionnel — requis pour '
              '${binaryPath != null ? '--binary' : '--image'}.',
          '$ociTool not found or not working — required for '
              '${binaryPath != null ? '--binary' : '--image'}.'));
      exit(1);
    }
    if (verbose) {
      print(
          '$ociTool : ${(ociCheck.stdout as String).split('\n').first.trim()}');
    }

    final refType = OciParser.detectRefType(imageRef);
    if (refType == OciRefType.binary) {
      print(tr('Analyse du binaire via $ociTool : $imageRef…',
          'Analysing binary via $ociTool: $imageRef…'));
    } else {
      final refTypeLabel = switch (refType) {
        OciRefType.registry => tr('registre', 'registry'),
        OciRefType.tar => tr('archive tar', 'tar archive'),
        OciRefType.ociLayout => 'OCI layout',
        OciRefType.binary =>
          tr('binaire', 'binary'), // inatteignable (branche ci-dessus)
      };
      print(tr(
          'Analyse de l\'image OCI ($refTypeLabel) via $ociTool : $imageRef…',
          'Analysing OCI image ($refTypeLabel) via $ociTool: $imageRef…'));
    }

    try {
      final ociResult =
          await OciParser().parseImage(imageRef, ociTool, verbose: verbose);
      ociPackages.addAll(ociResult.packages);
      ociOs = ociResult.os;
      print(tr('${ociPackages.length} paquet(s) trouvé(s) dans l\'image.',
          '${ociPackages.length} package(s) found in the image.'));
      if (verbose && ociOs != null) {
        print(tr('OS de base détecté : ${ociOs.id} ${ociOs.version}',
            'Base OS detected: ${ociOs.id} ${ociOs.version}'));
      }
    } catch (e) {
      _err(tr('Échec de l\'analyse OCI : $e', 'OCI analysis failed: $e'));
      exit(1);
    }
  }

  // --- Analyse par couche (--per-layer) ---
  LayerAnalysis? layerAnalysis;
  if (perLayer) {
    print(tr('Analyse par couche (mode $layerMode) via $ociTool…',
        'Per-layer analysis ($layerMode mode) via $ociTool…'));
    try {
      final parser = OciParser();
      if (layerMode == 'metadata') {
        final at =
            await parser.layerAttribution(imageRef!, ociTool, verbose: verbose);
        layerAnalysis =
            metadataLayerAnalysis(at.layers, at.layerOf, ociPackages);
        final unattributed =
            ociPackages.where((p) => !at.layerOf.containsKey(p.bomRef)).length;
        if (unattributed > 0) {
          stderr.writeln(tr(
              '⚠  $unattributed paquet(s) sans couche d\'origine '
                  'connue — absents des SBOM de couche.',
              '⚠  $unattributed package(s) with no known originating '
                  'layer — absent from the layer SBOMs.'));
        }
      } else {
        layerAnalysis = await parser.rootfsLayerAnalysis(imageRef!, ociTool,
            verbose: verbose, log: print);
      }
      print(tr('${layerAnalysis.layers.length} couche(s) analysée(s).',
          '${layerAnalysis.layers.length} layer(s) analysed.'));
    } catch (e) {
      _err(tr('Échec de l\'analyse par couche : $e',
          'Per-layer analysis failed: $e'));
      exit(1);
    }
  }

  // --- Detect tool availability ---
  final hasRpm = mainRefs.any((r) =>
      !r.endsWith('.whl') &&
      !_isTar(r) &&
      !r.endsWith('.deb') &&
      !r.endsWith('.zip') &&
      !_isJar(r));
  final hasWhl = mainRefs.any((r) => r.endsWith('.whl'));
  final hasTar = mainRefs.any(_isTar);
  final hasZip = mainRefs.any((r) => r.endsWith('.zip'));
  final hasDeb = mainRefs.any((r) => r.endsWith('.deb'));
  final hasJar = mainRefs.any(_isJar);

  if (hasRpm) {
    final rpmCheck = await Process.run('rpm', ['--version']);
    if (rpmCheck.exitCode != 0) {
      _err(tr('binaire rpm introuvable ou non fonctionnel.',
          'rpm binary not found or not functional.'));
      exit(1);
    }
    if (verbose) print('rpm: ${(rpmCheck.stdout as String).trim()}');
  }

  if (hasWhl || hasTar || hasZip) {
    final py3Check = await Process.run('python3', ['--version']);
    if (py3Check.exitCode != 0) {
      _err(tr(
          'python3 introuvable — requis pour lire les archives .whl, tar et zip.',
          'python3 not found — required to read .whl, tar, and zip archives.'));
      exit(1);
    }
    if (verbose) print('python3: ${(py3Check.stdout as String).trim()}');
  }

  if (hasDeb) {
    final debCheck = await Process.run('dpkg-deb', ['--version']);
    if (debCheck.exitCode != 0) {
      _err(tr('dpkg-deb introuvable — requis pour lire les fichiers .deb.',
          'dpkg-deb not found — required to read .deb files.'));
      exit(1);
    }
    if (verbose)
      print(
          'dpkg-deb: ${(debCheck.stdout as String).split('\n').first.trim()}');
  }

  if (hasJar) {
    final unzipCheck = await Process.run('unzip', ['-v']);
    if (unzipCheck.exitCode != 0) {
      _err(tr('unzip introuvable — requis pour lire les fichiers .jar.',
          'unzip not found — required to read .jar files.'));
      exit(1);
    }
    if (verbose) {
      print('unzip: ${(unzipCheck.stdout as String).split('\n').first.trim()}');
    }
  }

  // --- Parse packages ---
  final total = mainRefs.length +
      (preloadedPackages.isNotEmpty ? 1 : 0) +
      ociPackages.length;
  final conLabel =
      concurrencyN == 0 ? tr('illimité', 'unlimited') : '$concurrencyN';
  if (mainRefs.isNotEmpty) {
    print(tr(
        'Interrogation de ${mainRefs.length} paquet(s) — concurrence : $conLabel'
            '${preloadedPackages.isNotEmpty ? " (+ ${preloadedPackages.length} depuis les manifestes)" : ""}…',
        'Querying ${mainRefs.length} package(s) — concurrency: $conLabel'
            '${preloadedPackages.isNotEmpty ? " (+ ${preloadedPackages.length} from manifests)" : ""}…'));
  }

  final rpmParser = RpmParser();
  final whlParser = WheelParser();
  final tarParser = TarParser();
  final zipParser = ZipParser();
  final debParser = DebParser();
  final jarParser = JarParser();

  final mainTotal = mainRefs.length;
  final sem = _Semaphore(
      concurrencyN == 0 ? mainTotal.clamp(1, 1 << 20) : concurrencyN);
  int completed = 0;

  final rawResults = await Future.wait(
    List<Future<List<Package>>>.generate(mainTotal, (i) async {
      var ref = mainRefs[i];

      // Resolve bare RPM name to a local file when --rpm-dir is set
      if (rpmDir != null &&
          !ref.contains('/') &&
          !ref.endsWith('.whl') &&
          !ref.endsWith('.deb') &&
          !ref.endsWith('.zip') &&
          !_isTar(ref) &&
          !_isJar(ref)) {
        final resolved = rpmExactIndex[ref] ??
            (() {
              final paths = rpmNameIndex[ref];
              if (paths == null || paths.isEmpty) return null;
              if (paths.length > 1) {
                stderr.writeln('Warning: ' +
                    tr(
                      'plusieurs fichiers RPM correspondent à "$ref" ; '
                          'utilisation de ${paths.first.split('/').last}',
                      'multiple RPM files match "$ref"; '
                          'using ${paths.first.split('/').last}',
                    ));
              }
              return paths.first;
            })();
        if (resolved != null) ref = resolved;
      }

      await sem.acquire();
      try {
        List<Package> pkgs;
        if (ref.endsWith('.whl')) {
          final pkg = await whlParser.parseWheelFile(ref);
          pkgs = pkg != null ? [pkg] : const [];
        } else if (_isTar(ref)) {
          final pkg = await tarParser.parseTarFile(ref);
          pkgs = pkg != null ? [pkg] : const [];
        } else if (ref.endsWith('.zip')) {
          final pkg = await zipParser.parseZipFile(ref);
          pkgs = pkg != null ? [pkg] : const [];
        } else if (ref.endsWith('.deb')) {
          final pkg = await debParser.parseDebFile(ref);
          pkgs = pkg != null ? [pkg] : const [];
        } else if (_isJar(ref)) {
          // Un .jar « shaded »/uber-jar peut embarquer une ou plusieurs
          // dépendances relocalisées : chacune ressort comme un paquet
          // supplémentaire, en plus du jar lui-même.
          pkgs = await jarParser.parseJarFile(ref);
        } else {
          final pkg = await rpmParser.parsePackage(ref);
          pkgs = pkg != null ? [pkg] : const [];
        }
        completed++;
        final label = ref.contains('/') ? ref.split('/').last : ref;
        _printProgress(completed, mainTotal, label);
        return pkgs;
      } finally {
        sem.release();
      }
    }),
  );

  if (mainTotal > 0) stdout.writeln();

  final packages = <Package>[];
  final failedRefs = <String>[];
  for (int i = 0; i < rawResults.length; i++) {
    final pkgs = rawResults[i];
    if (pkgs.isNotEmpty) {
      packages.addAll(pkgs);
    } else {
      failedRefs.add(mainRefs[i]);
    }
  }
  final failed = failedRefs.length;

  // --- Descente dans les objets imbriqués (--depth) ---
  final nestedObjects = <NestedObject>[];
  var nestedCount = 0;
  if (nestedDepth > 0) {
    final explorer = NestedExplorer(
      maxDepth: nestedDepth,
      sdkVersions: sdkVersions,
      pubCache: pubCacheDir,
      flutterRoot: flutterRootDir,
      onProgress: verbose ? (l) => print('  ↳ $l') : null,
    );
    final roots = <(String, String?)>[
      for (var i = 0; i < mainRefs.length; i++)
        if (rawResults[i].isNotEmpty &&
            NestedExplorer.isExplorable(mainRefs[i]) &&
            File(mainRefs[i]).existsSync())
          (mainRefs[i], rawResults[i].first.bomRef),
    ];
    if (roots.isEmpty) {
      stderr.writeln(tr(
          '--depth : aucun objet de --input dans lequel descendre '
              '(rpm, deb, tar, zip, jar, wheel).',
          '--depth: no --input object to descend into '
              '(rpm, deb, tar, zip, jar, wheel).'));
    } else {
      print(tr(
          'Descente dans ${roots.length} objet(s) (profondeur '
              '${nestedDepth == maxNestedDepth ? 'max' : nestedDepth})…',
          'Descending into ${roots.length} object(s) (depth '
              '${nestedDepth == maxNestedDepth ? 'max' : nestedDepth})…'));
    }
    for (final (path, primaryRef) in roots) {
      final res = await explorer.explore(path, rootPrimaryRef: primaryRef);
      nestedObjects.addAll(res.objects);
      for (final w in res.warnings) {
        stderr.writeln('⚠  $w');
      }
    }
    nestedCount = nestedObjects.fold<int>(0, (n, o) => n + o.packages.length);
    print(tr(
        '$nestedCount composant(s) trouvé(s) dans '
            '${nestedObjects.length} objet(s) imbriqué(s).',
        '$nestedCount component(s) found in '
            '${nestedObjects.length} nested object(s).'));
    for (final o in nestedObjects) {
      packages.addAll(o.packages);
    }
  }

  packages.addAll(preloadedPackages);
  packages.addAll(ociPackages);

  // --- Deduplicate ---
  final seenRefs = <String>{};
  var uniquePackages = <Package>[];
  int dupes = 0;
  for (final pkg in packages) {
    if (seenRefs.add(pkg.bomRef)) {
      uniquePackages.add(pkg);
    } else {
      dupes++;
    }
  }

  // --- Apply license overrides ---
  if (licenseOverrides.isNotEmpty) {
    uniquePackages = _applyLicenseOverrides(uniquePackages, licenseOverrides);
    if (verbose) {
      final n = uniquePackages
          .where((p) => licenseOverrides.containsKey(p.name))
          .length;
      print(tr('Substitutions de licence appliquées à $n paquet(s).',
          'License overrides applied to $n package(s).'));
    }
  }

  // --- Apply supplier fallback ---
  final supplierFallback = (args['supplier'] as String?)?.trim() ?? '';
  if (supplierFallback.isNotEmpty) {
    final before = uniquePackages.where((p) => p.vendor.trim().isEmpty).length;
    uniquePackages = _applySupplierFallback(uniquePackages, supplierFallback);
    if (verbose) {
      print(tr(
          'Fournisseur par défaut "$supplierFallback" appliqué à $before '
              'paquet(s) sans fournisseur détecté.',
          'Supplier fallback "$supplierFallback" applied to $before '
              'package(s) without a detected supplier.'));
    }
  }

  // Mêmes surcharges (licence, fournisseur) sur les composants des couches.
  if (layerAnalysis != null &&
      (licenseOverrides.isNotEmpty || supplierFallback.isNotEmpty)) {
    layerAnalysis = layerAnalysis.map((p) => _applySupplierFallback(
            _applyLicenseOverrides([p], licenseOverrides), supplierFallback)
        .single);
  }

  // Mêmes surcharges (licence, fournisseur) sur les SBOM d'objets imbriqués.
  final nestedJobs = <({List<Package> pkgs, String location})>[];
  for (final o in nestedObjects) {
    var pkgs = o.packages;
    if (licenseOverrides.isNotEmpty) {
      pkgs = _applyLicenseOverrides(pkgs, licenseOverrides);
    }
    if (supplierFallback.isNotEmpty) {
      pkgs = _applySupplierFallback(pkgs, supplierFallback);
    }
    nestedJobs.add((pkgs: pkgs, location: o.location));
  }

  final failedNote =
      failed > 0 ? tr('  ($failed échec(s))', '  ($failed failure(s))') : '';
  final dupeNote = dupes > 0
      ? tr('  ($dupes doublon(s) supprimé(s))',
          '  ($dupes duplicate(s) removed)')
      : '';
  print(tr(
      'Analysés : ${uniquePackages.length}/${total + nestedCount} paquet(s).$failedNote$dupeNote',
      'Analysed: ${uniquePackages.length}/${total + nestedCount} package(s).$failedNote$dupeNote'));

  // --- Error report ---
  if (failedRefs.isNotEmpty) {
    stderr.writeln('');
    stderr.writeln(tr('⚠  ${failedRefs.length} paquet(s) ignoré(s) :',
        '⚠  ${failedRefs.length} package(s) skipped:'));
    for (final r in failedRefs) {
      final name = r.contains('/') ? r.split('/').last : r;
      stderr.writeln('   • $name');
    }
    stderr.writeln('');
  }

  if (uniquePackages.isEmpty) {
    _err(tr('Aucun paquet n\'a pu être analysé. Abandon.',
        'No packages could be parsed. Aborting.'));
    exit(1);
  }

  // --- Build dependency graph (skipped when all formats are markdown) ---
  final dependencies = <PackageDependency>[];
  if (formats.any((f) => f != 'markdown' && f != 'asciidoc' && f != 'html')) {
    print(tr('Résolution des dépendances…', 'Resolving dependencies…'));
    dependencies.addAll(rpmParser.buildDependencies(uniquePackages));
    if (nestedObjects.isNotEmpty) {
      final known = {for (final p in uniquePackages) p.bomRef};
      final withNested = withNestedDependencies(dependencies, nestedObjects);
      dependencies
        ..clear()
        ..addAll([
          for (final d in withNested)
            if (known.contains(d.sourceRef))
              PackageDependency(
                  sourceRef: d.sourceRef,
                  dependsOn: d.dependsOn.where(known.contains).toList()),
        ]);
    }
    final relCount =
        dependencies.fold<int>(0, (sum, d) => sum + d.dependsOn.length);
    print(tr('$relCount relation(s) de dépendance trouvée(s) dans la liste.',
        'Found $relCount intra-list dependency relationship(s).'));

    if (verbose) {
      for (final dep in dependencies.where((d) => d.dependsOn.isNotEmpty)) {
        final srcName = uniquePackages
            .firstWhere((p) => p.bomRef == dep.sourceRef,
                orElse: () => uniquePackages.first)
            .name;
        print(tr('  $srcName → ${dep.dependsOn.length} dépendance(s)',
            '  $srcName → ${dep.dependsOn.length} dep(s)'));
      }
    }
  }

  // --- Generate SBOM (loop over requested formats) ---
  final needsDeps =
      formats.any((f) => f != 'markdown' && f != 'asciidoc' && f != 'html');
  Future<void> writeAll(
    List<Package> pkgs,
    List<PackageDependency> deps,
    String Function(String fmt) pathFor, {
    LayerAnnotations? layers,
    String label = 'SBOM',
    String? docNameOverride,
  }) async {
    final effDocName = docNameOverride ?? docName;
    for (final fmt in formats) {
      final outPath = pathFor(fmt);
      print(tr('Génération de $label ($fmt)…', 'Generating $label ($fmt)…'));
      try {
        switch (fmt) {
          case 'cyclonedx':
            await CycloneDxGenerator().writeToFile(pkgs, deps, outPath,
                documentName: effDocName,
                specVersion: cycloneDxVersion,
                tlp: tlp,
                citationSource: citationSource,
                patentsByPackageName: patentMap,
                osInfo: ociOs,
                sdkTools: sdkVersions,
                layers: layers);
          case 'spdx':
            await SpdxGenerator().writeToFile(pkgs, deps, outPath,
                documentName: effDocName,
                osInfo: ociOs,
                sdkTools: sdkVersions,
                layers: layers);
          case 'spdx3':
            await Spdx3Generator().writeToFile(pkgs, deps, outPath,
                documentName: effDocName,
                osInfo: ociOs,
                sdkTools: sdkVersions,
                layers: layers);
          case 'json':
            await SimpleJsonGenerator().writeToFile(pkgs, deps, outPath,
                documentName: effDocName, layers: layers);
          case 'markdown':
            await MarkdownGenerator().writeToFile(pkgs, outPath,
                documentName: effDocName, layers: layers);
          case 'asciidoc':
            await AsciidocGenerator().writeToFile(pkgs, outPath,
                documentName: effDocName, layers: layers);
          case 'html':
            await HtmlGenerator().writeToFile(pkgs, outPath,
                documentName: effDocName, layers: layers);
          case 'csv':
            await CsvGenerator().writeToFile(pkgs, outPath,
                documentName: effDocName, layers: layers);
        }
      } catch (e, st) {
        _err(tr('Échec d\'écriture de $label ($fmt) : $e',
            'Failed to write $label ($fmt): $e'));
        if (verbose) stderr.writeln(st);
        exit(1);
      }
      final sz = await File(outPath).length();
      // Ligne lue par la GUI (sbom_runner.dart) : ne pas traduire.
      print('SBOM written → $outPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
    }
  }

  // --per-layer : un SBOM par couche en plus du global. Les identifiants de
  // document sont fixés d'avance, pour que global et couches se référencent
  // mutuellement ; le global est écrit en premier (premier fichier produit,
  // celui que la GUI ouvre par défaut).
  final layerJobs = <({
    List<Package> pkgs,
    String fileBase,
    String label,
    LayerAnnotations layers,
  })>[];
  LayerAnnotations? globalLayers;
  if (layerAnalysis != null) {
    final analysis = layerAnalysis;
    final globalUuid = generateUuidV4();
    final layerBase = _basePath(outputPath);
    final globalFileBase = layerBase.split('/').last;
    final total = analysis.layers.length;
    final summaries = <LayerSummary>[];
    for (var i = 0; i < total; i++) {
      final layer = analysis.layers[i];
      final delta = analysis.deltas[i];
      final fileBase = layerFileBase(layerBase, layer, total);
      final summary = LayerSummary(
        layer: layer,
        total: total,
        added: delta.added.length,
        modified: delta.modified.length,
        removed: delta.removed.length,
        fileBase: fileBase.split('/').last,
        documentUuid: generateUuidV4(),
      );
      summaries.add(summary);
      layerJobs.add((
        pkgs: delta.packages,
        fileBase: fileBase,
        label: tr('SBOM couche ${layer.index}/$total',
            'SBOM layer ${layer.index}/$total'),
        layers: LayerAnnotations.forLayer(
          mode: analysis.mode,
          self: summary,
          delta: delta,
          documentUuid: summary.documentUuid,
          globalUuid: globalUuid,
          globalFileBase: globalFileBase,
        ),
      ));
    }
    globalLayers = LayerAnnotations.forGlobal(
      mode: analysis.mode,
      layers: summaries,
      originByRef: analysis.origins(),
      documentUuid: globalUuid,
    );
  }

  final outputBase = formats.length > 1 ? _basePath(outputPath) : null;
  await writeAll(
    uniquePackages,
    dependencies,
    (fmt) =>
        outputBase != null ? '$outputBase${_formatExtension(fmt)}' : outputPath,
    layers: globalLayers,
  );

  final layerPrimaryPaths = <String>[];
  for (final job in layerJobs) {
    await writeAll(
      job.pkgs,
      needsDeps ? rpmParser.buildDependencies(job.pkgs) : const [],
      (fmt) => '${job.fileBase}${_formatExtension(fmt)}',
      label: job.label,
      layers: job.layers,
    );
    layerPrimaryPaths.add('${job.fileBase}${_formatExtension(formats.first)}');
  }

  // --depth : un SBOM par objet imbriqué (après le global, comme --per-layer).
  final nestedPrimaryPaths = <String>[];
  if (nestedFiles) {
    final nestedBase = _basePath(outputPath);
    for (var i = 0; i < nestedJobs.length; i++) {
      final job = nestedJobs[i];
      final fileBase =
          nestedFileBase(nestedBase, i + 1, nestedJobs.length, job.location);
      await writeAll(
        job.pkgs,
        needsDeps ? rpmParser.buildDependencies(job.pkgs) : const [],
        (fmt) => '$fileBase${_formatExtension(fmt)}',
        label: tr('SBOM objet imbriqué ${i + 1}/${nestedJobs.length}',
            'SBOM nested object ${i + 1}/${nestedJobs.length}'),
        docNameOverride: '${docName ?? 'Package Set SBOM'} — ${job.location}',
      );
      nestedPrimaryPaths.add('$fileBase${_formatExtension(formats.first)}');
    }
  }

  // ── Vérification des politiques ──────────────────────────────────────────
  final checker = PolicyChecker();
  int policyFailures = 0;

  if (denyLicenses.isNotEmpty) {
    final violations = checker.checkDenyLicenses(uniquePackages, denyLicenses);
    if (violations.isNotEmpty) {
      stderr.writeln(tr(
          '\nPolitique licence : ${violations.length} violation(s) :',
          '\nLicense policy: ${violations.length} violation(s):'));
      for (final v in violations) {
        stderr.writeln('  [DENY] ${v.packageName} ${v.version} — ${v.license}');
      }
      policyFailures += violations.length;
    } else if (verbose) {
      print(tr('Politiques licences : OK', 'License policies: OK'));
    }
  }

  if (minQualityScore != null) {
    final threshold = double.tryParse(minQualityScore);
    if (threshold == null) {
      stderr.writeln(tr(
          '--min-quality-score : valeur invalide "$minQualityScore"',
          '--min-quality-score: invalid value "$minQualityScore"'));
      exit(1);
    }
    final primaryOut = formats.length == 1
        ? outputPath
        : '${_basePath(outputPath)}${_formatExtension(formats.first)}';
    final score = await checker.runSbomqs(primaryOut, verbose: verbose);
    if (score != null) {
      if (score < threshold) {
        stderr.writeln(tr(
            '\nPolitique qualité : score=$score < seuil=$threshold → ÉCHEC',
            '\nQuality policy: score=$score < threshold=$threshold → FAIL'));
        policyFailures++;
      } else if (verbose) {
        print(tr('Politique qualité : score=$score >= seuil=$threshold → OK',
            'Quality policy: score=$score >= threshold=$threshold → OK'));
      }
    }
  }

  // ── Signature cosign ─────────────────────────────────────────────────────
  if (signSbom) {
    final primaryOut = formats.length == 1
        ? outputPath
        : '${_basePath(outputPath)}${_formatExtension(formats.first)}';
    await _signWithCosign(primaryOut, verbose: verbose);
    for (final p in [...layerPrimaryPaths, ...nestedPrimaryPaths]) {
      await _signWithCosign(p, verbose: verbose);
    }
  }

  if (policyFailures > 0) {
    stderr.writeln(tr(
        '\n$policyFailures politique(s) violée(s) — code retour 2',
        '\n$policyFailures policy violation(s) — exit code 2'));
    exit(2);
  }
}

// ── Sous-commande diff ────────────────────────────────────────────────────────

Future<void> _runDiff(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('output',
        abbr: 'o',
        help: tr('Fichier de sortie (JSON). Défaut : affichage console.',
            'Output file (JSON). Default: console output.'))
    ..addFlag('json',
        defaultsTo: false,
        negatable: false,
        help: tr('Sortie au format JSON structuré.', 'Structured JSON output.'))
    ..addFlag('no-color',
        defaultsTo: false,
        negatable: false,
        help: tr('Désactive la coloration ANSI.', 'Disable ANSI colouring.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.', 'Help.'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('diff: ${e.message}');
    _printDiffUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printDiffUsage(parser);
    exit(0);
  }

  final rest = args.rest;
  if (rest.length != 2) {
    stderr.writeln(tr('diff: deux fichiers SBOM requis.',
        'diff: two SBOM files are required.'));
    _printDiffUsage(parser);
    exit(1);
  }

  final Map<String, dynamic> before, after;
  try {
    before = await SbomDiffer.loadFile(rest[0]);
    after = await SbomDiffer.loadFile(rest[1]);
  } catch (e) {
    stderr.writeln('diff: $e');
    exit(1);
  }

  final differ = SbomDiffer();
  final result = differ.diff(before, after);

  if (args['json'] as bool || (args['output'] as String?) != null) {
    final jsonStr =
        const JsonEncoder.withIndent('  ').convert(differ.toJson(result));
    final outPath = args['output'] as String?;
    if (outPath != null) {
      await File(outPath).writeAsString(jsonStr);
      print(tr('Diff écrit → $outPath', 'Diff written → $outPath'));
    } else {
      print(jsonStr);
    }
  } else {
    differ.printDiff(result, color: !(args['no-color'] as bool));
  }

  exit(result.isEmpty ? 0 : 1);
}

void _printDiffUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator diff – Compare deux fichiers SBOM et affiche les changements.

Usage:
  sbom_generator diff <avant.cdx.json> <après.cdx.json> [options]

${parser.usage}

Codes de retour:
  0  Aucun changement
  1  Des changements ont été détectés
''', '''
sbom_generator diff – Compares two SBOM files and shows the changes.

Usage:
  sbom_generator diff <before.cdx.json> <after.cdx.json> [options]

${parser.usage}

Exit codes:
  0  No change
  1  Changes were detected
'''));
}

// ── Sous-commande merge ───────────────────────────────────────────────────────

Future<void> _runMerge(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('output',
        abbr: 'o',
        mandatory: true,
        help: tr(
            'Fichier SBOM fusionné de sortie (même format que le premier '
                'fichier d\'entrée : .cdx.json ou .spdx.json).',
            'Output merged SBOM file (same format as the first input '
                'file: .cdx.json or .spdx.json).'))
    ..addOption('name',
        abbr: 'n',
        help: tr('Nom du document SBOM fusionné.',
            'Name of the merged SBOM document.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.', 'Help.'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('merge: ${e.message}');
    _printMergeUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printMergeUsage(parser);
    exit(0);
  }

  final files = args.rest;
  if (files.length < 2) {
    stderr.writeln(tr('merge: au moins deux fichiers SBOM requis.',
        'merge: at least two SBOM files are required.'));
    _printMergeUsage(parser);
    exit(1);
  }

  final sboms = <Map<String, dynamic>>[];
  for (final f in files) {
    try {
      sboms.add(await SbomDiffer.loadFile(f));
    } catch (e) {
      stderr.writeln('merge: $e');
      exit(1);
    }
  }

  final merger = SbomMerger();
  final merged = merger.merge(sboms, documentName: args['name'] as String?);
  final outPath = args['output'] as String;
  await File(outPath)
      .writeAsString(const JsonEncoder.withIndent('  ').convert(merged));
  final total =
      (merged['components'] as List? ?? merged['packages'] as List? ?? [])
          .length;
  print(tr('Fusion de ${files.length} SBOMs → $total composant(s) → $outPath',
      'Merged ${files.length} SBOMs → $total component(s) → $outPath'));
}

void _printMergeUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator merge – Fusionne plusieurs fichiers SBOM en un seul.

Usage:
  sbom_generator merge <a.cdx.json> <b.cdx.json> [...] -o merged.cdx.json

${parser.usage}
''', '''
sbom_generator merge – Merges several SBOM files into one.

Usage:
  sbom_generator merge <a.cdx.json> <b.cdx.json> [...] -o merged.cdx.json

${parser.usage}
'''));
}

// ── Signature cosign ──────────────────────────────────────────────────────────

Future<void> _signWithCosign(String sbomPath, {bool verbose = false}) async {
  final check = await Process.run('cosign', ['version']);
  if (check.exitCode != 0) {
    stderr.writeln(tr('sign: cosign introuvable — signature ignorée.',
        'sign: cosign not found — signature skipped.'));
    return;
  }
  if (verbose)
    print(tr('cosign : signature de $sbomPath…', 'cosign: signing $sbomPath…'));
  final result = await Process.run('cosign', [
    'sign-blob',
    '--yes',
    '--bundle',
    '$sbomPath.bundle',
    sbomPath,
  ]);
  if (result.exitCode != 0) {
    stderr.writeln(tr(
        'cosign: échec (code ${result.exitCode}) : ${result.stderr}',
        'cosign: failed (code ${result.exitCode}): ${result.stderr}'));
  } else {
    print('Signature → $sbomPath.bundle');
  }
}

bool _isTar(String ref) =>
    ref.endsWith('.tar') || ref.endsWith('.tar.gz') || ref.endsWith('.tgz');

bool _isJar(String ref) =>
    ref.endsWith('.jar') || ref.endsWith('.war') || ref.endsWith('.ear');

/// True si --input pointe directement vers une archive/un paquet unique
/// plutôt que vers un fichier liste (une référence par ligne).
bool _isSingleArchiveInput(String path) =>
    path.endsWith('.zip') ||
    _isTar(path) ||
    path.endsWith('.whl') ||
    path.endsWith('.deb') ||
    path.endsWith('.rpm') ||
    _isJar(path);

bool _isRequirements(String ref) =>
    ref.endsWith('.txt') && !ref.endsWith('.whl');

bool _isGoSum(String ref) => ref.endsWith('go.sum');
bool _isGoMod(String ref) => ref.endsWith('go.mod');
bool _isPackageLock(String ref) => ref.endsWith('package-lock.json');
bool _isYarnLock(String ref) => ref.endsWith('yarn.lock');
bool _isPomXml(String ref) => ref.endsWith('pom.xml');
bool _isPubspecLock(String ref) => ref.endsWith('pubspec.lock');
bool _isPubspecYaml(String ref) => ref.endsWith('pubspec.yaml');

/// True si [path] est un fichier reconnu par le scan récursif d'un dossier
/// passé en --input (voir la lecture de packageRefs plus haut). Contrairement
/// au fichier liste, seuls les noms exacts sont acceptés pour les manifestes
/// (ex. `requirements.txt`, pas n'importe quel `.txt`) afin d'éviter les faux
/// positifs lors d'un scan automatique.
bool _isSupportedPackageFile(String path) {
  final base = path.split('/').last;
  return path.endsWith('.rpm') ||
      path.endsWith('.deb') ||
      path.endsWith('.whl') ||
      _isJar(path) ||
      path.endsWith('.zip') ||
      _isTar(path) ||
      base == 'requirements.txt' ||
      base == 'pom.xml' ||
      base == 'go.sum' ||
      base == 'go.mod' ||
      base == 'package-lock.json' ||
      base == 'yarn.lock' ||
      base == 'pubspec.lock' ||
      base == 'pubspec.yaml';
}

/// Le préfixe `Error:` est lu par la GUI (coloration, erreur fatale) : jamais
/// traduit — seul le message l'est.
void _err(String msg) => stderr.writeln('Error: $msg');

void _printProgress(int current, int total, String label) {
  const barWidth = 32;

  final ratio = total == 0 ? 1.0 : current / total;
  final filled = (ratio * barWidth).round().clamp(0, barWidth);
  final bar = '${'█' * filled}${'░' * (barWidth - filled)}';

  final pct = '${(ratio * 100).round().toString().padLeft(3)}%';
  final count = '${current.toString().padLeft(total.toString().length)}/$total';

  const prefix = '  ';
  final head = '[$bar] $count  $pct  ';
  final maxLabel = 120 - prefix.length - head.length;
  final shortLabel = label.length > maxLabel
      ? '…${label.substring(label.length - maxLabel + 1)}'
      : label;

  stdout.write('\r$prefix$head$shortLabel\x1B[K');
}

class _Semaphore {
  _Semaphore(int count) : _count = count;
  int _count;
  final _waiters = <Completer<void>>[];

  Future<void> acquire() async {
    if (_count > 0) {
      _count--;
      return;
    }
    final waiter = Completer<void>();
    _waiters.add(waiter);
    await waiter.future;
  }

  void release() {
    if (_waiters.isNotEmpty) {
      _waiters.removeAt(0).complete();
    } else {
      _count++;
    }
  }
}

// ── Format helpers ────────────────────────────────────────────────────────────

String _formatExtension(String format) => switch (format) {
      'cyclonedx' => '.cdx.json',
      'spdx' => '.spdx.json',
      'spdx3' => '.spdx3.jsonld',
      'json' => '.custom.json',
      'markdown' => '.md',
      'asciidoc' => '.adoc',
      'html' => '.html',
      'csv' => '.csv',
      _ => '.json',
    };

/// Retire les extensions SBOM connues de [output] pour obtenir un chemin de base.
String _basePath(String output) {
  const exts = [
    '.cdx.json',
    '.spdx.json',
    '.spdx3.jsonld',
    '.custom.json',
    '.jsonld',
    '.json',
    '.md',
    '.adoc',
    '.csv',
  ];
  for (final ext in exts) {
    if (output.endsWith(ext)) {
      return output.substring(0, output.length - ext.length);
    }
  }
  return output;
}

// ── License override helpers ──────────────────────────────────────────────────

/// Analyse un fichier de substitution de licences (une ligne « nom: expression-SPDX »).
Map<String, String> _parseLicenseMap(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    _err(tr('Fichier de correspondance de licences introuvable : $path',
        'License map file not found: $path'));
    exit(1);
  }
  final result = <String, String>{};
  for (final line in file.readAsLinesSync()) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
    final idx = trimmed.indexOf(':');
    if (idx < 1) continue;
    final name = trimmed.substring(0, idx).trim();
    final license = trimmed.substring(idx + 1).trim();
    if (name.isNotEmpty && license.isNotEmpty) result[name] = license;
  }
  return result;
}

// ── Patent map helpers (CycloneDX 1.7) ────────────────────────────────────────

/// Analyse un fichier de déclarations de brevets (CycloneDX 1.7 `patentAssertions`).
/// Une ligne par paquet : `package_name: patentNumber|jurisdiction|legalStatus|assertionType`.
/// Exemple : `openssl: US1234567|US|granted|license`.
Map<String, PatentAssertion> _parsePatentMap(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    _err(tr('Fichier de brevets introuvable : $path',
        'Patent map file not found: $path'));
    exit(1);
  }
  final result = <String, PatentAssertion>{};
  for (final line in file.readAsLinesSync()) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
    final idx = trimmed.indexOf(':');
    if (idx < 1) continue;
    final name = trimmed.substring(0, idx).trim();
    final fields = trimmed.substring(idx + 1).trim().split('|');
    if (name.isEmpty || fields.length != 4) {
      _err(tr(
          '--patent-map : ligne invalide (attendu "name: number|jurisdiction|status|type") : "$trimmed"',
          '--patent-map: invalid line (expected "name: number|jurisdiction|status|type"): "$trimmed"'));
      exit(1);
    }
    result[name] = PatentAssertion(
      patentNumber: fields[0].trim(),
      jurisdiction: fields[1].trim(),
      legalStatus: fields[2].trim(),
      assertionType: fields[3].trim(),
    );
  }
  return result;
}

// ── Sous-commande scan ────────────────────────────────────────────────────────

Future<void> _runScan(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('sbom',
        abbr: 's',
        help: tr(
            'Chemin vers le fichier SBOM à analyser (.cdx.json, .spdx.json…).\n'
                'Exclusif de --image.',
            'Path to the SBOM file to analyse (.cdx.json, .spdx.json…).\n'
                'Mutually exclusive with --image.'))
    ..addOption('image',
        abbr: 'I',
        help: tr(
            'Image de conteneur à analyser (registre, archive tar, OCI\n'
                'layout) : son SBOM CycloneDX est d\'abord généré (via\n'
                '--oci-tool) dans un répertoire temporaire, puis scanné.\n'
                'Exclusif de --sbom.',
            'Container image to analyse (registry, tar archive, OCI\n'
                'layout): its CycloneDX SBOM is first generated (via\n'
                '--oci-tool) in a temporary directory, then scanned.\n'
                'Mutually exclusive with --sbom.'))
    ..addOption('package',
        abbr: 'p',
        help: tr(
            'Paquet ou archive local à analyser directement (rpm, deb,\n'
                'tar/tgz, zip, jar/war/ear, wheel) : son SBOM CycloneDX est\n'
                'd\'abord généré (voir --depth) dans un répertoire temporaire,\n'
                'puis scanné. Exclusif de --sbom et --image.',
            'Local package or archive to analyse directly (rpm, deb,\n'
                'tar/tgz, zip, jar/war/ear, wheel): its CycloneDX SBOM is\n'
                'first generated (see --depth) in a temporary directory,\n'
                'then scanned. Mutually exclusive with --sbom and --image.'))
    ..addOption('depth',
        defaultsTo: '0',
        help: tr(
            'Avec --package : profondeur de descente dans les objets\n'
                'imbriqués (0 = l\'objet seul, N niveaux, all = sans limite),\n'
                'comme --depth de la génération. Chaque CVE est rattachée à\n'
                'l\'objet qui contient le paquet vulnérable (colonne OBJET).',
            'With --package: depth of descent into nested objects\n'
                '(0 = the object alone, N levels, all = unlimited), like the\n'
                'generation --depth. Each CVE is attached to the object that\n'
                'contains the vulnerable package (OBJECT column).'))
    ..addOption('oci-tool',
        defaultsTo: 'syft',
        allowed: _validOciTools,
        help: tr('Backend de génération du SBOM pour --image.',
            'SBOM generation backend for --image.'))
    ..addFlag('per-layer',
        negatable: false,
        help: tr(
            'Vulnérabilités par couche d\'image. Avec --sbom, le SBOM doit\n'
                'être le SBOM global d\'un jeu produit par --per-layer (SBOM de\n'
                'couche à côté) ; avec --image, le jeu est généré.',
            'Vulnerabilities per image layer. With --sbom, the SBOM must\n'
                'be the global SBOM of a set produced by --per-layer (layer\n'
                'SBOMs alongside); with --image, the set is generated.'))
    ..addOption('layer-scan',
        allowed: validLayerScanModes,
        defaultsTo: 'attribute',
        help: tr(
            'Méthode de --per-layer :\n'
                '  attribute  un scan du SBOM global, chaque CVE rattachée à la\n'
                '             couche d\'origine de son paquet (défaut)\n'
                '  each       SBOM de chaque couche scanné séparément (CVE\n'
                '             introduites puis corrigées plus haut incluses)',
            '--per-layer method:\n'
                '  attribute  one scan of the global SBOM, each CVE attached to\n'
                '             the originating layer of its package (default)\n'
                '  each       each layer SBOM scanned separately (CVEs\n'
                '             introduced then fixed higher up included)'))
    ..addOption('layer-mode',
        allowed: validLayerModes,
        help: tr(
            'Avec --image --per-layer : calcul des couches (voir\n'
                '--layer-mode de la génération ; défaut metadata pour\n'
                'syft/trivy, rootfs sinon).',
            'With --image --per-layer: layer computation (see the\n'
                'generation --layer-mode; default metadata for\n'
                'syft/trivy, rootfs otherwise).'))
    ..addOption('scanner',
        abbr: 'S',
        defaultsTo: 'grype',
        help: tr(
            'Scanner(s) à utiliser.\n'
                '  grype   Anchore Grype\n'
                '  osv     Google OSV-Scanner\n'
                '  trivy   Aqua Security Trivy\n'
                '  all     Les trois scanners',
            'Scanner(s) to use.\n'
                '  grype   Anchore Grype\n'
                '  osv     Google OSV-Scanner\n'
                '  trivy   Aqua Security Trivy\n'
                '  all     All three scanners'))
    ..addOption('cve-after',
        help: tr(
            'N\'afficher que les CVE publiées/modifiées après cette date (YYYY-MM-DD)',
            'Only show CVEs published/modified after this date (YYYY-MM-DD)'))
    ..addOption('cve-before',
        help: tr(
            'N\'afficher que les CVE publiées/modifiées avant cette date (YYYY-MM-DD)',
            'Only show CVEs published/modified before this date (YYYY-MM-DD)'))
    ..addOption('cve-date-field',
        defaultsTo: 'published',
        help: tr(
            'Champ de date à utiliser pour le filtre.\n'
                '  published   Date de publication (défaut)\n'
                '  modified    Date de dernière modification\n'
                '  latest      La plus récente des deux',
            'Date field to use for the filter.\n'
                '  published   Publication date (default)\n'
                '  modified    Last modification date\n'
                '  latest      The more recent of the two'))
    ..addFlag('include-undated',
        defaultsTo: false,
        negatable: false,
        help: tr('Inclure les CVE sans date dans les résultats filtrés',
            'Include undated CVEs in the filtered results'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'text',
        help: tr(
            'Format de sortie.\n'
                '  text      Texte coloré sur stdout (défaut)\n'
                '  sarif     SARIF 2.1.0 (intégration GitHub Code Scanning)\n'
                '  markdown  Rapport de synthèse inter-scanners (Markdown)\n'
                '  asciidoc  Rapport de synthèse inter-scanners (AsciiDoc)\n'
                '  pdf       Idem asciidoc + conversion via asciidoctor-pdf',
            'Output format.\n'
                '  text      Coloured text on stdout (default)\n'
                '  sarif     SARIF 2.1.0 (GitHub Code Scanning integration)\n'
                '  markdown  Cross-scanner summary report (Markdown)\n'
                '  asciidoc  Cross-scanner summary report (AsciiDoc)\n'
                '  pdf       Same as asciidoc + conversion via asciidoctor-pdf'))
    ..addOption('output',
        abbr: 'o',
        help: tr(
            'Fichier de sortie. Requis pour --format markdown/asciidoc/pdf ;\n'
                'pour --format sarif, écrit sur stdout si omis.',
            'Output file. Required for --format markdown/asciidoc/pdf;\n'
                'for --format sarif, written to stdout if omitted.'))
    ..addOption('color',
        allowed: ['auto', 'always', 'never'],
        defaultsTo: 'auto',
        help: tr(
            'Coloration ANSI des alertes Critical/High (formats rapport).\n'
                '  auto    si stdout est un terminal et NO_COLOR non défini (défaut)\n'
                '  always  toujours (utile derrière un pipe : build-dist.sh)\n'
                '  never   jamais (préfixes [CRITICAL]/[HIGH])',
            'ANSI colouring of Critical/High alerts (report formats).\n'
                '  auto    if stdout is a terminal and NO_COLOR is unset (default)\n'
                '  always  always (useful behind a pipe: build-dist.sh)\n'
                '  never   never ([CRITICAL]/[HIGH] prefixes)'))
    ..addFlag('enrich',
        defaultsTo: true,
        help: tr(
            'Enrichir chaque CVE avec les signaux d\'exploitabilité :\n'
                '  CISA KEV (exploitée dans la nature), EPSS (probabilité),\n'
                '  PoC public, sous-score d\'exploitabilité CVSS.\n'
                '  --no-enrich : hors-ligne, uniquement ce que les scanners\n'
                '  fournissent déjà + le cache local. Forcé par SBOMGEN_OFFLINE=1.',
            'Enrich each CVE with exploitability signals:\n'
                '  CISA KEV (exploited in the wild), EPSS (probability),\n'
                '  public PoC, CVSS exploitability sub-score.\n'
                '  --no-enrich: offline, only what the scanners already\n'
                '  provide + the local cache. Forced by SBOMGEN_OFFLINE=1.'))
    ..addFlag('poc',
        defaultsTo: true,
        help: tr(
            'Interroger la source PoC tierce (poc-in-github). --no-poc\n'
                'garde KEV/EPSS et la maturité « E: » du vecteur CVSS.',
            'Query the third-party PoC source (poc-in-github). --no-poc\n'
                'keeps KEV/EPSS and the "E:" maturity of the CVSS vector.'))
    ..addOption('enrich-timeout',
        defaultsTo: '8',
        help: tr('Délai maximal (secondes) par requête d\'enrichissement.',
            'Maximum delay (seconds) per enrichment request.'))
    ..addFlag('only-kev',
        negatable: false,
        help: tr('Ne garder que les CVE présentes au catalogue CISA KEV.',
            'Keep only the CVEs listed in the CISA KEV catalog.'))
    ..addOption('epss-min',
        help: tr(
            'Ne garder que les CVE dont le score EPSS est ≥ cette valeur '
                '(0..1, ex. 0.1).',
            'Keep only the CVEs whose EPSS score is ≥ this value '
                '(0..1, e.g. 0.1).'))
    ..addOption('sort',
        allowed: ['severity', 'risk'],
        defaultsTo: 'severity',
        help: tr(
            'Ordre d\'affichage console.\n'
                '  severity  pire sévérité d\'abord (défaut)\n'
                '  risk      KEV, puis EPSS décroissant, puis sévérité',
            'Console display order.\n'
                '  severity  worst severity first (default)\n'
                '  risk      KEV, then EPSS descending, then severity'))
    ..addFlag('help',
        abbr: 'h',
        negatable: false,
        help: tr('Afficher l\'aide de la sous-commande scan',
            'Show the scan subcommand help'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('scan: ${e.message}');
    _printScanUsage(parser);
    exit(1);
  }

  if (args['help'] as bool) {
    _printScanUsage(parser);
    exit(0);
  }

  final imageRef = args['image'] as String?;
  final packageRef = args['package'] as String?;
  if ([args['sbom'], imageRef, packageRef].where((v) => v != null).length !=
      1) {
    stderr.writeln(tr(
        'scan: indiquer --sbom <fichier>, --image <image> ou '
            '--package <fichier> (exactement l\'un des trois).',
        'scan: specify --sbom <file>, --image <image> or '
            '--package <file> (exactly one of the three).'));
    _printScanUsage(parser);
    exit(1);
  }
  final scanDepthRaw = args['depth'] as String;
  final scanDepth = parseNestedDepth(scanDepthRaw);
  if (scanDepth == null) {
    stderr.writeln(tr(
        'scan: --depth attend un entier ≥ 0 ou "all" (reçu "$scanDepthRaw").',
        'scan: --depth expects an integer ≥ 0 or "all" (got "$scanDepthRaw").'));
    exit(1);
  }
  if (args.wasParsed('depth') && packageRef == null) {
    stderr.writeln(tr('scan: --depth nécessite --package.',
        'scan: --depth requires --package.'));
    exit(1);
  }
  if (packageRef != null) {
    if (args['per-layer'] as bool) {
      stderr.writeln(tr(
          'scan: --per-layer ne s\'applique qu\'aux images '
              '(--image / --sbom d\'un jeu par couche).',
          'scan: --per-layer only applies to images '
              '(--image / --sbom of a per-layer set).'));
      exit(1);
    }
    if (!File(packageRef).existsSync()) {
      stderr.writeln(tr('scan: fichier introuvable : $packageRef',
          'scan: file not found: $packageRef'));
      exit(1);
    }
  }
  final perLayer = args['per-layer'] as bool;
  final layerScan = args['layer-scan'] as String;
  final layerMode = args['layer-mode'] as String?;
  if (layerMode != null && (imageRef == null || !perLayer)) {
    stderr.writeln(tr('scan: --layer-mode nécessite --image et --per-layer.',
        'scan: --layer-mode requires --image and --per-layer.'));
    exit(1);
  }
  var sbomFile = (args['sbom'] as String?) ?? '';
  final scanner = args['scanner'] as String;
  final dateField = args['cve-date-field'] as String;
  final includeUndated = args['include-undated'] as bool;
  final format = args['format'] as String;
  final colorMode = args['color'] as String;
  final outputPath = args['output'] as String?;
  final offlineEnv = Platform.environment['SBOMGEN_OFFLINE'] == '1';
  final enrich = (args['enrich'] as bool) && !offlineEnv;
  final wantPoc = args['poc'] as bool;
  final onlyKev = args['only-kev'] as bool;
  final sortMode = args['sort'] as String;

  double? epssMin;
  final rawEpssMin = args['epss-min'] as String?;
  if (rawEpssMin != null) {
    epssMin = double.tryParse(rawEpssMin);
    if (epssMin == null || epssMin < 0 || epssMin > 1) {
      stderr.writeln(tr(
          'scan: --epss-min doit être un nombre entre 0 et 1 '
              '(reçu "$rawEpssMin")',
          'scan: --epss-min must be a number between 0 and 1 '
              '(got "$rawEpssMin")'));
      exit(1);
    }
  }
  var enrichTimeout = int.tryParse(args['enrich-timeout'] as String) ?? 8;
  if (enrichTimeout < 1) enrichTimeout = 8;

  if (!_validScanners.contains(scanner)) {
    stderr.writeln(tr(
        'scan: scanner invalide "$scanner". Valides : ${_validScanners.join(', ')}',
        'scan: invalid scanner "$scanner". Valid: ${_validScanners.join(', ')}'));
    exit(1);
  }
  if (!_validDateFields.contains(dateField)) {
    stderr.writeln(tr(
        'scan: cve-date-field invalide "$dateField". Valides : ${_validDateFields.join(', ')}',
        'scan: invalid cve-date-field "$dateField". Valid: ${_validDateFields.join(', ')}'));
    exit(1);
  }
  if (!_validScanFormats.contains(format)) {
    stderr.writeln(tr(
        'scan: format invalide "$format". Valides : ${_validScanFormats.join(', ')}',
        'scan: invalid format "$format". Valid: ${_validScanFormats.join(', ')}'));
    exit(1);
  }
  if (imageRef == null &&
      packageRef == null &&
      !await File(sbomFile).exists()) {
    stderr.writeln(tr('scan: fichier SBOM introuvable : $sbomFile',
        'scan: SBOM file not found: $sbomFile'));
    exit(1);
  }

  DateTime? after, before;
  final rawAfter = args['cve-after'] as String?;
  final rawBefore = args['cve-before'] as String?;
  if (rawAfter != null) {
    after = DateTime.tryParse(rawAfter);
    if (after == null) {
      stderr.writeln(tr(
          'scan: format de date invalide pour --cve-after : "$rawAfter" (attendu YYYY-MM-DD)',
          'scan: invalid date format for --cve-after: "$rawAfter" (expected YYYY-MM-DD)'));
      exit(1);
    }
  }
  if (rawBefore != null) {
    before = DateTime.tryParse(rawBefore);
    if (before == null) {
      stderr.writeln(tr(
          'scan: format de date invalide pour --cve-before : "$rawBefore" (attendu YYYY-MM-DD)',
          'scan: invalid date format for --cve-before: "$rawBefore" (expected YYYY-MM-DD)'));
      exit(1);
    }
    // La date "avant" est inclusive en fin de journée
    before = before.add(const Duration(hours: 23, minutes: 59, seconds: 59));
  }

  final isReport = _reportScanFormats.contains(format);
  if (isReport && outputPath == null) {
    stderr.writeln(tr(
        'scan: --output <fichier> est requis pour --format $format.',
        'scan: --output <file> is required for --format $format.'));
    exit(1);
  }

  final scanners = scanner == 'all' ? ['grype', 'osv', 'trivy'] : [scanner];

  final quiet = format == 'sarif' || isReport;

  // --image : SBOM (et SBOM de couche) générés dans un répertoire temporaire,
  // supprimé avant chaque sortie.
  Directory? tmpDir;
  Future<Never> quit(int code) async {
    final dir = tmpDir;
    if (dir != null) {
      await Process.run('chmod', ['-R', 'u+rwX', dir.path]);
      await dir.delete(recursive: true);
    }
    exit(code);
  }

  if (packageRef != null) {
    tmpDir = await Directory.systemTemp.createTemp('sbom_scan_');
    sbomFile = '${tmpDir.path}/package.cdx.json';
    stderr.writeln(tr(
        'Génération du SBOM de $packageRef'
            '${scanDepth > 0 ? ' (profondeur ${scanDepth == maxNestedDepth ? 'max' : scanDepth})' : ''}…',
        'Generating the SBOM of $packageRef'
            '${scanDepth > 0 ? ' (depth ${scanDepth == maxNestedDepth ? 'max' : scanDepth})' : ''}…'));
    final code = await _runSelf([
      '-i',
      packageRef,
      '--depth',
      '$scanDepth',
      '--no-nested-files',
      '-f',
      'cyclonedx',
      '-o',
      sbomFile,
    ]);
    if (code != 0 || !File(sbomFile).existsSync()) {
      stderr.writeln(tr(
          'scan: échec de la génération du SBOM de $packageRef (code $code).',
          'scan: SBOM generation failed for $packageRef (code $code).'));
      await quit(1);
    }
  }

  if (imageRef != null) {
    tmpDir = await Directory.systemTemp.createTemp('sbom_scan_');
    sbomFile = '${tmpDir.path}/image.cdx.json';
    stderr.writeln(tr('Génération du SBOM de l\'image $imageRef…',
        'Generating the SBOM of image $imageRef…'));
    final code = await _runSelf([
      '--image',
      imageRef,
      '--oci-tool',
      args['oci-tool'] as String,
      '-f',
      'cyclonedx',
      '-o',
      sbomFile,
      if (perLayer) '--per-layer',
      if (layerMode != null) ...['--layer-mode', layerMode],
    ]);
    if (code != 0 || !File(sbomFile).existsSync()) {
      stderr.writeln(tr(
          'scan: échec de la génération du SBOM de $imageRef (code $code).',
          'scan: SBOM generation failed for $imageRef (code $code).'));
      await quit(1);
    }
  }

  LayeredSbomSet? layerSet;
  if (perLayer) {
    layerSet = LayeredSbomSet.load(sbomFile);
    if (layerSet == null || layerSet.layers.isEmpty) {
      stderr.writeln(tr(
          'scan: $sbomFile ne porte aucune information de couche '
              '— produire le SBOM avec --per-layer (ou utiliser --image).',
          'scan: $sbomFile carries no layer information '
              '— produce the SBOM with --per-layer (or use --image).'));
      await quit(1);
    }
  }

  // Rattachement des CVE aux objets imbriqués (SBOM produit avec --depth).
  final nestedIndex =
      imageRef == null && !perLayer ? NestedSbomIndex.load(sbomFile) : null;
  final rootLabel = (packageRef ?? sbomFile).split('/').last;

  final resultsByScanner = <String, List<Map<String, dynamic>>>{};
  for (final s in scanners) {
    List<Map<String, dynamic>>? vulns;
    if (layerSet != null && layerScan == 'each') {
      // Un scan par SBOM de couche ; chaque résultat porte sa couche.
      if (!quiet) {
        stdout.writeln('\n── ${_scannerTitle(s)} '
            '(${tr('par couche', 'per layer')}) ──────────────────────────');
      }
      for (final l in layerSet.layers) {
        if (l.path == null) continue;
        final found = await _runScanner(s, l.path!, quiet: true);
        if (found == null) continue;
        for (final v in found) {
          v['layer'] = l.index;
        }
        (vulns ??= []).addAll(found);
      }
    } else {
      vulns = await _runScanner(s, sbomFile, quiet: quiet);
      if (vulns != null && layerSet != null) {
        final unknown = attributeLayers(vulns, layerSet);
        if (unknown > 0 && !quiet) {
          stderr.writeln(tr(
              '  $unknown résultat(s) sans couche d\'origine connue '
                  '(paquet absent du SBOM global).',
              '  $unknown result(s) with no known originating layer '
                  '(package absent from the global SBOM).'));
        }
      }
    }
    if (vulns == null) continue;
    if (nestedIndex != null && !nestedIndex.isEmpty) {
      attributeNested(vulns, nestedIndex, rootLabel);
    }
    resultsByScanner[s] =
        _filterByDate(vulns, dateField, after, before, includeUndated);
  }

  // Enrichissement CVE (exploitabilité / exploitation active) — une passe pour
  // tous les scanners, avant les filtres --only-kev / --epss-min.
  final exploitById = await _enrichFindings(
    resultsByScanner,
    enrich: enrich,
    poc: wantPoc,
    timeoutSeconds: enrichTimeout,
    quiet: quiet,
  );

  if (onlyKev || epssMin != null) {
    for (final s in resultsByScanner.keys.toList()) {
      resultsByScanner[s] =
          _filterByExploit(resultsByScanner[s]!, onlyKev, epssMin);
    }
  }

  int totalShown = 0;
  for (final s in scanners) {
    final filtered = resultsByScanner[s];
    if (filtered == null) continue;
    if (!quiet) {
      _printScanResults(s, filtered, after, before, dateField, sortMode);
    }
    totalShown += filtered.length;
  }
  if (!quiet && layerSet != null) {
    _printLayerSummary(resultsByScanner, layerSet, layerScan);
  }

  if (format == 'sarif') {
    final sarif = _buildSarifReport(
        resultsByScanner, imageRef ?? packageRef ?? sbomFile, exploitById);
    final json = const JsonEncoder.withIndent('  ').convert(sarif);
    if (outputPath != null) {
      await File(outputPath).writeAsString(json);
      stderr.writeln(
          tr('SARIF écrit → $outputPath', 'SARIF written → $outputPath'));
    } else {
      print(json);
    }
  }

  if (isReport) {
    if (resultsByScanner.isEmpty) {
      stderr.writeln(tr(
          'scan: aucun scanner n\'a produit de résultat — rapport non généré.',
          'scan: no scanner produced any result — report not generated.'));
      await quit(1);
    }
    final gen = ScanReportGenerator(
      sbomPath: imageRef != null
          ? tr('image $imageRef', 'image $imageRef')
          : (packageRef != null
              ? tr('paquet $packageRef', 'package $packageRef')
              : sbomFile),
      layers: layerSet?.layers ?? const [],
      layerScanMode: layerSet != null ? layerScan : null,
      resultsByScanner: resultsByScanner,
      exploitById: exploitById,
      toolVersions: {
        'sbom-generator': _version,
        for (final s in scanners)
          if (resultsByScanner.containsKey(s))
            {'grype': 'Grype', 'osv': 'OSV-Scanner', 'trivy': 'Trivy'}[s]!:
                await _scannerVersion(s) ?? tr('inconnue', 'unknown'),
      },
    );
    _printSeverityAlerts(gen, colorMode, exploitById);
    await _writeScanReport(format, outputPath!, gen);
    // Un rapport produit n'est pas un échec, quel que soit le nombre de CVE.
    await quit(0);
  }

  await quit(totalShown > 0 ? 1 : 0);
}

String _scannerTitle(String s) =>
    {'grype': 'Grype', 'osv': 'OSV-Scanner', 'trivy': 'Trivy'}[s] ?? s;

/// Relance ce même programme (script `dart` ou exécutable compilé) avec
/// [args], sa sortie renvoyée sur stderr (stdout peut porter du SARIF).
Future<int> _runSelf(List<String> args) async {
  final script = Platform.script.toFilePath();
  final viaVm = script.endsWith('.dart') ||
      script.endsWith('.snapshot') ||
      script.endsWith('.dill');
  final p = await Process.start(
      Platform.resolvedExecutable, [if (viaVm) script, ...args]);
  await Future.wait([
    p.stdout.forEach(stderr.add),
    p.stderr.forEach(stderr.add),
  ]);
  return p.exitCode;
}

/// Tableau console « CVE par couche » (`scan --per-layer`, format texte).
void _printLayerSummary(
  Map<String, List<Map<String, dynamic>>> resultsByScanner,
  LayeredSbomSet set,
  String layerScan,
) {
  stdout.writeln('\n── ${tr('CVE par couche', 'CVEs per layer')} '
      '(${layerScan == 'each' ? tr('scan de chaque couche', 'each layer scanned') : tr('rattachement au SBOM global', 'attributed from the global SBOM')}) ──────────');
  stdout.writeln(
      '${tr('COUCHE', 'LAYER').padRight(8)}  ${'DIGEST'.padRight(12)}  '
      '${'CVE'.padLeft(4)}  ${'CRIT'.padLeft(4)}  ${'HIGH'.padLeft(4)}  '
      '${tr('INSTRUCTION', 'INSTRUCTION')}');
  for (final l in summarizeByLayer(resultsByScanner, set.layers)) {
    final by = l.layer.createdBy ?? '';
    stdout.writeln('${'${l.layer.index}'.padRight(8)}  '
        '${l.layer.shortDigest.padRight(12)}  '
        '${'${l.total}'.padLeft(4)}  ${'${l.count('critical')}'.padLeft(4)}  '
        '${'${l.count('high')}'.padLeft(4)}  '
        '${by.length > 70 ? '${by.substring(0, 69)}…' : by}');
  }
}

/// Affiche, une ligne par CVE unique, les vulnérabilités Critical (rouge) et
/// High (orange) — pendant un build (`scan -f markdown|asciidoc|pdf`). Best
/// effort : n'échoue jamais et n'affecte pas le code de retour.
void _printSeverityAlerts(ScanReportGenerator gen, String colorMode,
    Map<String, ExploitInfo> exploitById) {
  final alerts = gen.alerts();
  if (alerts.isEmpty) return;

  final color = switch (colorMode) {
    'always' => true,
    'never' => false,
    _ => stdout.hasTerminal && !Platform.environment.containsKey('NO_COLOR'),
  };
  const red = '\x1B[1;31m', orange = '\x1B[38;5;208m', reset = '\x1B[0m';

  var crit = 0, high = 0, kevCount = 0;
  for (final a in alerts) {
    final isCrit = a.severity.toLowerCase() == 'critical';
    isCrit ? crit++ : high++;
    final label = isCrit ? 'CRITICAL' : 'HIGH';
    final srcs = a.scanners.isEmpty ? '' : '  (${a.scanners.join(', ')})';
    final pkg = a.package.isEmpty ? '' : '  ${a.package}';
    final e = exploitById[a.id] ?? ExploitInfo.empty;
    final marks = StringBuffer();
    if (e.inKev) {
      marks.write('  [KEV]');
      kevCount++;
    }
    if (e.epssScore != null) {
      marks.write('  EPSS ${e.epssScore!.toStringAsFixed(2)}');
    }
    if (e.pocKnown && !e.inKev) marks.write('  [PoC]');
    final line = '[$label] ${a.id}$pkg$srcs$marks';
    stdout.writeln(color ? '${isCrit ? red : orange}$line$reset' : line);
  }
  final kevSuffix = kevCount > 0
      ? tr(', dont $kevCount au catalogue CISA KEV',
          ', of which $kevCount in the CISA KEV catalog')
      : '';
  final summary = tr('→ $crit CVE critique(s), $high CVE High$kevSuffix',
      '→ $crit critical CVE(s), $high High CVE(s)$kevSuffix');
  stdout.writeln(color ? '$red$summary$reset' : summary);
}

/// Écrit le rapport de synthèse inter-scanners dans [outputPath].
/// Pour `pdf`, écrit d'abord un `.adoc` à côté puis lance `asciidoctor-pdf` ;
/// si l'exécutable est absent ou échoue, conserve le `.adoc` et avertit
/// (best-effort — l'appelant, ex. build-dist.sh, continue).
Future<void> _writeScanReport(
  String format,
  String outputPath,
  ScanReportGenerator gen,
) async {
  if (format == 'markdown') {
    await File(outputPath).writeAsString(gen.toMarkdown());
    stdout.writeln(tr('Rapport Markdown écrit → $outputPath',
        'Markdown report written → $outputPath'));
    return;
  }

  // asciidoc | pdf : on écrit toujours l'AsciiDoc.
  final adocPath = format == 'asciidoc'
      ? outputPath
      : (outputPath.toLowerCase().endsWith('.pdf')
          ? '${outputPath.substring(0, outputPath.length - 4)}.adoc'
          : '$outputPath.adoc');
  await File(adocPath).writeAsString(gen.toAsciiDoc());

  if (format == 'asciidoc') {
    stdout.writeln(tr('Rapport AsciiDoc écrit → $adocPath',
        'AsciiDoc report written → $adocPath'));
    return;
  }

  try {
    final r = await renderAsciiDocToPdf(adocPath, outputPath);
    if (r.exitCode == 0) {
      stdout.writeln(tr('Rapport PDF écrit → $outputPath',
          'PDF report written → $outputPath'));
    } else {
      stderr.writeln(tr(
          'scan: asciidoctor-pdf a échoué (code ${r.exitCode}) : '
              '${(r.stderr as String).trim()}',
          'scan: asciidoctor-pdf failed (code ${r.exitCode}): '
              '${(r.stderr as String).trim()}'));
      stderr.writeln(tr('scan: rapport AsciiDoc conservé → $adocPath',
          'scan: AsciiDoc report kept → $adocPath'));
    }
  } on ProcessException {
    stderr.writeln(tr(
        'scan: asciidoctor-pdf introuvable — PDF non généré, '
            'rapport AsciiDoc conservé → $adocPath',
        'scan: asciidoctor-pdf not found — PDF not generated, '
            'AsciiDoc report kept → $adocPath'));
  }
}

/// Version courte d'un scanner (`<x.y.z>`), ou null si l'outil est absent.
Future<String?> _scannerVersion(String scanner) async {
  final (cmd, cmdArgs) = switch (scanner) {
    'grype' => ('grype', ['version']),
    'osv' => ('osv-scanner', ['--version']),
    'trivy' => ('trivy', ['--version']),
    _ => (scanner, ['--version']),
  };
  try {
    final r = await Process.run(cmd, cmdArgs);
    final m = RegExp(r'(\d+\.\d+\.\d+)').firstMatch('${r.stdout}\n${r.stderr}');
    return m?.group(1);
  } catch (_) {
    return null;
  }
}

// Retourne la liste brute [{id, severity, package, published, modified}] ou null si erreur.
Future<List<Map<String, dynamic>>?> _runScanner(String scanner, String sbomFile,
    {bool quiet = false}) async {
  switch (scanner) {
    case 'grype':
      return _runGrype(sbomFile, quiet: quiet);
    case 'osv':
      return _runOsv(sbomFile, quiet: quiet);
    case 'trivy':
      return _runTrivy(sbomFile, quiet: quiet);
    default:
      return null;
  }
}

Future<List<Map<String, dynamic>>?> _runGrype(String sbomFile,
    {bool quiet = false}) async {
  if (!quiet)
    stdout.writeln('\n── Grype ──────────────────────────────────────────');
  final ProcessResult result;
  try {
    // Mêmes options que le lanceur Grype de la GUI
    // (gui/lib/services/grype_runner.dart), pour que `scan` et l'onglet
    // Grype rapportent les mêmes CVE sur un même SBOM :
    //   --add-cpes-if-none : Grype synthétise un CPE pour les composants qui
    //     n'en ont pas (sinon il ne matche que par PURL et rate les CVE
    //     indexées par CPE — ex. le pseudo-paquet `flutter` d'un pubspec) ;
    //   --by-cve : rapporte l'ID CVE plutôt que GHSA quand les deux existent,
    //     indispensable pour aligner les identifiants avec OSV-Scanner/Trivy
    //     dans la matrice inter-scanners du rapport de synthèse ;
    //   --platform linux : sans effet sur une entrée SBOM, gardé pour parité.
    result = await Process.run('grype', [
      sbomFile,
      '--output',
      'json',
      '--platform',
      'linux',
      '--add-cpes-if-none',
      '--by-cve',
    ]);
  } on ProcessException catch (e) {
    stderr.writeln(tr(
        'grype: introuvable (${e.message}). Installez-le ou omettez --scanner grype.',
        'grype: not found (${e.message}). Install it or omit --scanner grype.'));
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln(tr(
        'grype: erreur (code ${result.exitCode}) : ${result.stderr}',
        'grype: error (code ${result.exitCode}): ${result.stderr}'));
    return null;
  }
  try {
    final data = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final matches = data['matches'] as List? ?? [];
    return matches.map<Map<String, dynamic>>((m) {
      final vuln = m['vulnerability'] as Map<String, dynamic>? ?? {};
      final artifact = m['artifact'] as Map<String, dynamic>? ?? {};
      final fix = vuln['fix'] as Map<String, dynamic>? ?? const {};
      final (cvssVector, cvssBase) = _cvssFromGrype(vuln['cvss'] as List?);
      // Grype expose nativement CISA KEV et EPSS dans sa base — inutile
      // d'interroger le réseau pour ces CVE (cf. `VulnEnricher`, graine).
      final kev = (vuln['knownExploited'] as List?) ?? const [];
      final kev0 = kev.isNotEmpty ? kev.first as Map<String, dynamic> : null;
      final epss = (vuln['epss'] as List?) ?? const [];
      final epss0 = epss.isNotEmpty ? epss.first as Map<String, dynamic> : null;
      return {
        'id': vuln['id'] ?? '',
        'severity': vuln['severity'] ?? 'Unknown',
        'package': '${artifact['name'] ?? ''}@${artifact['version'] ?? ''}',
        'published': vuln['publishedDate'],
        'modified': vuln['lastModifiedDate'],
        // `fix.state` de Grype : `fixed` / `not-fixed` / `wont-fix` / `unknown`.
        // Pour les paquets de distribution, `wont-fix` reprend le statut
        // `<no-dsa>` du Debian Security Tracker (pas de mise à jour de sécurité
        // dédiée pour la release stable installée).
        'fixState': fix['state'] ?? '',
        'fixedVersions':
            (fix['versions'] as List?)?.map((e) => '$e').toList() ?? const [],
        if (cvssVector != null) 'cvssVector': cvssVector,
        if (cvssBase != null) 'cvssBaseScore': cvssBase,
        if (kev0 != null) 'kevSeed': true,
        if (kev0 != null) 'kevDateAdded': kev0['dateAdded'],
        if (kev0 != null) 'kevDueDate': kev0['dueDate'],
        if (kev0 != null)
          'kevRansomware':
              ((kev0['knownRansomwareCampaignUse'] as String?) ?? '')
                      .toLowerCase() ==
                  'known',
        if (epss0 != null) 'epssSeed': (epss0['epss'] as num?)?.toDouble(),
        if (epss0 != null)
          'epssPercentileSeed': (epss0['percentile'] as num?)?.toDouble(),
      };
    }).toList();
  } catch (e) {
    stderr.writeln(tr('grype: impossible de parser le JSON: $e',
        'grype: unable to parse the JSON: $e'));
    return null;
  }
}

Future<List<Map<String, dynamic>>?> _runOsv(String sbomFile,
    {bool quiet = false}) async {
  if (!quiet)
    stdout.writeln('\n── OSV-Scanner ─────────────────────────────────────');
  final ProcessResult result;
  try {
    result = await Process.run(
        'osv-scanner', ['--format', 'json', '--sbom', sbomFile]);
  } on ProcessException catch (e) {
    stderr.writeln(tr(
        'osv-scanner: introuvable (${e.message}). Installez-le ou omettez --scanner osv.',
        'osv-scanner: not found (${e.message}). Install it or omit --scanner osv.'));
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln(tr(
        'osv-scanner: erreur (code ${result.exitCode}) : ${result.stderr}',
        'osv-scanner: error (code ${result.exitCode}): ${result.stderr}'));
    return null;
  }
  try {
    final data = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final out = <Map<String, dynamic>>[];
    for (final res in (data['results'] as List? ?? [])) {
      for (final pkg in (res['packages'] as List? ?? [])) {
        final pkgInfo = (pkg['package'] as Map?) ?? {};
        final name = pkgInfo['name'] ?? '';
        final version = pkgInfo['version'] ?? '';
        for (final v in (pkg['vulnerabilities'] as List? ?? [])) {
          final aliases = (v['aliases'] as List?)?.cast<String>() ?? [];
          final cve =
              aliases.firstWhere((a) => a.startsWith('CVE-'), orElse: () => '');
          final dbSev =
              (v['database_specific'] as Map?)?['severity'] as String? ?? '';
          // Versions corrigées annoncées par OSV : événements `fixed` des
          // plages `affected[].ranges[]`. Pour un avis Debian, c'est souvent
          // la version de la branche `unstable`/`testing`, pas une mise à jour
          // installable sur la release stable — d'où la note du rapport.
          final fixed = <String>{};
          for (final aff in (v['affected'] as List? ?? [])) {
            for (final rg in ((aff as Map)['ranges'] as List? ?? [])) {
              for (final ev in ((rg as Map)['events'] as List? ?? [])) {
                final f = (ev as Map)['fixed'];
                if (f != null && '$f'.isNotEmpty) fixed.add('$f');
              }
            }
          }
          final (cvssVector, cvssBase) = _cvssFromOsv(v['severity'] as List?);
          out.add({
            'id': cve.isNotEmpty ? cve : v['id'] ?? '',
            'severity': dbSev.isNotEmpty ? dbSev : 'Unknown',
            'package': '$name@$version',
            'published': v['published'],
            'modified': v['modified'],
            'fixedVersions': fixed.toList(),
            if (cvssVector != null) 'cvssVector': cvssVector,
            if (cvssBase != null) 'cvssBaseScore': cvssBase,
          });
        }
      }
    }
    return out;
  } catch (e) {
    stderr.writeln(tr('osv-scanner: impossible de parser le JSON: $e',
        'osv-scanner: unable to parse the JSON: $e'));
    return null;
  }
}

Future<List<Map<String, dynamic>>?> _runTrivy(String sbomFile,
    {bool quiet = false}) async {
  if (!quiet)
    stdout.writeln('\n── Trivy ───────────────────────────────────────────');
  final ProcessResult result;
  try {
    result = await Process.run(
        'trivy', ['sbom', '--format', 'json', '--quiet', sbomFile]);
  } on ProcessException catch (e) {
    stderr.writeln(tr(
        'trivy: introuvable (${e.message}). Installez-le ou omettez --scanner trivy.',
        'trivy: not found (${e.message}). Install it or omit --scanner trivy.'));
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln(tr(
        'trivy: erreur (code ${result.exitCode}) : ${result.stderr}',
        'trivy: error (code ${result.exitCode}): ${result.stderr}'));
    return null;
  }
  try {
    final data = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final out = <Map<String, dynamic>>[];
    for (final res in (data['Results'] as List? ?? [])) {
      for (final v in (res['Vulnerabilities'] as List? ?? [])) {
        final fixedRaw = (v['FixedVersion'] as String?) ?? '';
        final (cvssVector, cvssBase) = _cvssFromTrivy(v['CVSS'] as Map?);
        out.add({
          'id': v['VulnerabilityID'] ?? '',
          'severity': v['Severity'] ?? 'Unknown',
          'package': '${v['PkgName'] ?? ''}@${v['InstalledVersion'] ?? ''}',
          'published': v['PublishedDate'],
          'modified': v['LastModifiedDate'],
          'fixedVersions': fixedRaw.isEmpty
              ? const <String>[]
              : fixedRaw
                  .split(RegExp(r'\s*(?:,|\|\|)\s*'))
                  .where((s) => s.isNotEmpty)
                  .toList(),
          if (cvssVector != null) 'cvssVector': cvssVector,
          if (cvssBase != null) 'cvssBaseScore': cvssBase,
        });
      }
    }
    return out;
  } catch (e) {
    stderr.writeln(tr('trivy: impossible de parser le JSON: $e',
        'trivy: unable to parse the JSON: $e'));
    return null;
  }
}

/// Vecteur CVSS + score de base retenus depuis le tableau `vulnerability.cvss`
/// de Grype : on préfère une entrée `Primary`, sinon la première avec un
/// vecteur non vide.
(String?, double?) _cvssFromGrype(List? cvss) {
  if (cvss == null || cvss.isEmpty) return (null, null);
  Map<String, dynamic>? best;
  for (final c in cvss) {
    final m = c as Map<String, dynamic>;
    if ((m['vector'] as String?)?.isNotEmpty != true) continue;
    best ??= m;
    if ((m['type'] as String?)?.toLowerCase() == 'primary') {
      best = m;
      break;
    }
  }
  if (best == null) return (null, null);
  final metrics = best['metrics'] as Map<String, dynamic>? ?? const {};
  return (
    best['vector'] as String?,
    (metrics['baseScore'] as num?)?.toDouble(),
  );
}

/// Vecteur CVSS + score depuis `vulnerabilities[].severity` d'OSV-Scanner
/// (`[{type: CVSS_V3|CVSS_V4, score: "CVSS:3.1/AV:N/..."}]` — le champ `score`
/// contient le vecteur). On garde la version la plus élevée disponible.
(String?, double?) _cvssFromOsv(List? severity) {
  if (severity == null || severity.isEmpty) return (null, null);
  String? pick;
  for (final s in severity) {
    final m = s as Map<String, dynamic>;
    final vec = m['score'] as String?;
    if (vec == null || !vec.startsWith('CVSS:')) continue;
    if (pick == null || vec.compareTo(pick) > 0) pick = vec;
  }
  return (pick, null);
}

/// Vecteur CVSS + score depuis la map `CVSS` de Trivy (`{nvd: {V3Vector,
/// V3Score, ...}, redhat: {...}}`). On préfère NVD, puis n'importe quelle
/// source fournissant un vecteur v3.
(String?, double?) _cvssFromTrivy(Map? cvss) {
  if (cvss == null || cvss.isEmpty) return (null, null);
  Map<String, dynamic>? src = (cvss['nvd'] as Map?)?.cast<String, dynamic>();
  src ??= cvss.values.whereType<Map>().cast<Map<String, dynamic>>().firstWhere(
      (m) => (m['V3Vector'] as String?)?.isNotEmpty == true,
      orElse: () => const {});
  final vec = src['V3Vector'] as String?;
  final score = (src['V3Score'] as num?)?.toDouble();
  return ((vec?.isNotEmpty == true) ? vec : null, score);
}

final RegExp _distroCveRe = RegExp(r'^[A-Z]+-(CVE-\d{4}-\d+)$');

/// Retire un préfixe d'avis de distribution (`DEBIAN-CVE-2026-1` → `CVE-2026-1`)
/// pour dédupliquer entre scanners — même logique que `ScanReportGenerator`.
String _normalizeCveId(String id) =>
    _distroCveRe.firstMatch(id)?.group(1) ?? id;

/// Enrichit tous les findings (tous scanners) avec leur [ExploitInfo] : KEV,
/// EPSS, PoC public, sous-score d'exploitabilité CVSS. Une seule passe réseau.
/// Best-effort : toute erreur laisse un [ExploitInfo.empty]. Retourne la map
/// id normalisé → [ExploitInfo] (consommée par le rapport de synthèse).
Future<Map<String, ExploitInfo>> _enrichFindings(
  Map<String, List<Map<String, dynamic>>> resultsByScanner, {
  required bool enrich,
  required bool poc,
  required int timeoutSeconds,
  required bool quiet,
}) async {
  final ids = <String>{};
  final seed = <String, CveSeed>{};
  for (final vulns in resultsByScanner.values) {
    for (final v in vulns) {
      final id = _normalizeCveId((v['id'] as String?) ?? '');
      if (id.isEmpty) continue;
      ids.add(id);
      final s = CveSeed(
        cvssVector: v['cvssVector'] as String?,
        cvssBaseScore: (v['cvssBaseScore'] as num?)?.toDouble(),
        kev: v['kevSeed'] == true,
        kevDateAdded: _parseDate(v['kevDateAdded'] as String?),
        kevDueDate: _parseDate(v['kevDueDate'] as String?),
        kevRansomware: v['kevRansomware'] == true,
        epssScore: (v['epssSeed'] as num?)?.toDouble(),
        epssPercentile: (v['epssPercentileSeed'] as num?)?.toDouble(),
      );
      seed[id] = seed.containsKey(id) ? seed[id]!.merge(s) : s;
    }
  }
  if (ids.isEmpty) return const {};

  Map<String, ExploitInfo> byId;
  try {
    byId = await VulnEnricher(
      enableNetwork: enrich,
      enablePoc: enrich && poc,
      timeout: Duration(seconds: timeoutSeconds),
    ).enrich(ids, seed: seed);
  } catch (e) {
    if (!quiet) {
      stderr.writeln(tr('scan: enrichissement CVE indisponible ($e)',
          'scan: CVE enrichment unavailable ($e)'));
    }
    byId = {for (final id in ids) id: ExploitInfo.empty};
  }

  for (final vulns in resultsByScanner.values) {
    for (final v in vulns) {
      v['exploit'] = byId[_normalizeCveId((v['id'] as String?) ?? '')] ??
          ExploitInfo.empty;
    }
  }
  return byId;
}

/// Applique `--only-kev` / `--epss-min` sur des findings déjà enrichis.
List<Map<String, dynamic>> _filterByExploit(
  List<Map<String, dynamic>> vulns,
  bool onlyKev,
  double? epssMin,
) {
  if (!onlyKev && epssMin == null) return vulns;
  return vulns.where((v) {
    final e = v['exploit'] as ExploitInfo? ?? ExploitInfo.empty;
    if (onlyKev && !e.inKev) return false;
    if (epssMin != null && (e.epssScore ?? 0) < epssMin) return false;
    return true;
  }).toList();
}

List<Map<String, dynamic>> _filterByDate(
  List<Map<String, dynamic>> vulns,
  String field,
  DateTime? after,
  DateTime? before,
  bool includeUndated,
) {
  if (after == null && before == null) return vulns;
  return vulns.where((v) {
    final pub = _parseDate(v['published'] as String?);
    final mod = _parseDate(v['modified'] as String?);
    final date = switch (field) {
      'published' => pub,
      'modified' => mod,
      'latest' => _latestDate(pub, mod),
      _ => pub,
    };
    if (date == null) return includeUndated;
    if (after != null && date.isBefore(after)) return false;
    if (before != null && date.isAfter(before)) return false;
    return true;
  }).toList();
}

DateTime? _parseDate(String? s) {
  if (s == null || s.isEmpty) return null;
  try {
    return DateTime.parse(s).toUtc();
  } catch (_) {
    return null;
  }
}

DateTime? _latestDate(DateTime? a, DateTime? b) {
  if (a == null) return b;
  if (b == null) return a;
  return b.isAfter(a) ? b : a;
}

void _printScanResults(
  String scanner,
  List<Map<String, dynamic>> vulns,
  DateTime? after,
  DateTime? before,
  String field,
  String sortMode,
) {
  final sevOrder = {
    'Critical': 0,
    'CRITICAL': 0,
    'High': 1,
    'HIGH': 1,
    'Medium': 2,
    'MEDIUM': 2,
    'Low': 3,
    'LOW': 3,
    'Unknown': 4,
    'UNKNOWN': 4
  };
  ExploitInfo ex(Map<String, dynamic> v) =>
      v['exploit'] as ExploitInfo? ?? ExploitInfo.empty;
  if (sortMode == 'risk') {
    vulns.sort((a, b) => ex(b)
        .riskScore(b['severity'] as String? ?? '')
        .compareTo(ex(a).riskScore(a['severity'] as String? ?? '')));
  } else {
    vulns.sort((a, b) =>
        (sevOrder[a['severity']] ?? 5).compareTo(sevOrder[b['severity']] ?? 5));
  }

  final filterDesc = StringBuffer();
  if (after != null || before != null) {
    filterDesc.write(tr('  Filtre : champ=$field', '  Filter: field=$field'));
    if (after != null) {
      filterDesc.write(
          tr('  après=${_formatDate(after)}', '  after=${_formatDate(after)}'));
    }
    if (before != null) {
      filterDesc.write(tr(
          '  avant=${_formatDate(before)}', '  before=${_formatDate(before)}'));
    }
  }
  stdout.writeln(tr('  ${vulns.length} CVE(s) trouvée(s)$filterDesc',
      '  ${vulns.length} CVE(s) found$filterDesc'));

  if (vulns.isEmpty) return;

  const w0 = 10, w1 = 20, w2 = 30, w3 = 4, w4 = 10;
  final withLayer = vulns.any((v) => v['layer'] != null);
  final withContainer = vulns.any((v) => v['container'] != null);
  stdout.writeln('${tr('SÉVÉRITÉ', 'SEVERITY').padRight(w0)}  '
      '${'CVE / ID'.padRight(w1)}  '
      '${tr('PAQUET', 'PACKAGE').padRight(w2)}  ${'KEV'.padRight(w3)}  '
      '${'EPSS'.padRight(w4)}  '
      '${withLayer ? tr('PoC  COUCHE', 'PoC  LAYER') : 'PoC'}'
      '${withContainer ? tr('  OBJET', '  OBJECT') : ''}');
  stdout.writeln('${'-' * w0}  ${'-' * w1}  ${'-' * w2}  ${'-' * w3}  '
      '${'-' * w4}  ---${withLayer ? '  ------' : ''}'
      '${withContainer ? '  -----' : ''}');
  for (final v in vulns) {
    final e = ex(v);
    final sev = (v['severity'] as String).padRight(w0);
    final id = (v['id'] as String).padRight(w1);
    final pkg = (v['package'] as String).padRight(w2);
    final kev = (e.inKev ? '✓' : '—').padRight(w3);
    final epss = (e.epssScore == null
            ? '—'
            : '${e.epssScore!.toStringAsFixed(2)} p'
                '${((e.epssPercentile ?? 0) * 100).round()}')
        .padRight(w4);
    final poc = e.pocCount > 0
        ? '✓${e.pocCount}'
        : (e.pocKnown
            ? '✓'
            : (e.hasAnySignal || e.cvssVector != null ? '—' : '?'));
    final layer = withLayer ? '  ${poc.padRight(3)}  ${v['layer'] ?? '?'}' : '';
    final container = withContainer ? '  ${v['container'] ?? '?'}' : '';
    stdout.writeln(withLayer
        ? '$sev  $id  $pkg  $kev  $epss$layer$container'
        : '$sev  $id  $pkg  $kev  $epss  $poc$container');
  }
}

String _formatDate(DateTime d) => '${d.year.toString().padLeft(4, '0')}-'
    '${d.month.toString().padLeft(2, '0')}-'
    '${d.day.toString().padLeft(2, '0')}';

void _printScanUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator scan – Analyser les CVE d'un fichier SBOM avec filtre par date.

Usage:
  sbom-generator scan --sbom <fichier.cdx.json> [options]
  sbom-generator scan --image <image> [--per-layer] [options]
  sbom-generator scan --package <rpm|deb|tgz|zip|jar…> [--depth N] [options]

${parser.usage}

Exemples:
  # Toutes les CVE grype depuis 2024
  sbom-generator scan --sbom sbom.cdx.json --cve-after 2024-01-01

  # CVE OSV-Scanner entre deux dates
  sbom-generator scan --sbom sbom.cdx.json --scanner osv \\
    --cve-after 2023-06-01 --cve-before 2024-01-01

  # Tous les scanners, champ modification, CVE sans date incluses
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --cve-date-field modified --cve-after 2023-01-01 --include-undated

  # Export SARIF (GitHub Code Scanning) vers un fichier
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --format sarif --output results.sarif

  # Rapport de synthèse PDF (Grype + OSV-Scanner + Trivy)
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --format pdf --output scan-report.pdf

  # Seulement les CVE activement exploitées (CISA KEV), triées par risque
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --only-kev --sort risk

  # Prioriser : CVE avec une probabilité d'exploitation EPSS ≥ 10 %
  sbom-generator scan --sbom sbom.cdx.json --epss-min 0.1

  # Hors-ligne : pas de requête réseau (KEV/EPSS/PoC seulement via Grype + cache)
  sbom-generator scan --sbom sbom.cdx.json --no-enrich

  # CVE par couche d'une image (SBOM généré à la volée, un scan rattaché)
  sbom-generator scan --image ./app.tar --per-layer --scanner all

  # Idem, SBOM de chaque couche scanné (couches calculées en mode rootfs),
  # rapport PDF avec section « Couches de l'image »
  sbom-generator scan --image nginx:latest --per-layer --layer-scan each \\
    --layer-mode rootfs --scanner all -f pdf -o nginx-layers.pdf

  # À partir d'un jeu déjà produit par sbom-generator --per-layer
  sbom-generator scan --sbom out/app.cdx.json --per-layer

  # Scanner directement un RPM et les jars qu'il contient (2 niveaux) ;
  # chaque CVE indique l'objet (rpm, jar…) qui contient le paquet vulnérable
  sbom-generator scan --package app-1.0-1.x86_64.rpm --depth 2 --scanner all

  # Archive : tout ce qu'elle contient, sans limite de profondeur
  sbom-generator scan --package release.tar.gz --depth all

Enrichissement : chaque CVE est complétée par CISA KEV (exploitée dans la
nature), EPSS (probabilité d'exploitation à 30 jours), un signal PoC public
et le sous-score d'exploitabilité CVSS. Actif par défaut ; --no-enrich (ou
SBOMGEN_OFFLINE=1) le désactive, --no-poc ne coupe que la source tierce.

En --format markdown/asciidoc/pdf, chaque CVE Critical (rouge) et High
(orange) est aussi listée sur stdout, une ligne par CVE unique
(dédupliquée entre scanners), avec les marqueurs [KEV] / EPSS / [PoC] —
utile pendant un build. --color auto par défaut (couleur si stdout est un
terminal et NO_COLOR non défini) ; --color always force la couleur
derrière un pipe.

Codes de retour:
  text / sarif :
    0  Aucune CVE dans la plage demandée
    1  Au moins une CVE trouvée (ou erreur de scanner)
  markdown / asciidoc / pdf :
    0  Rapport produit (quel que soit le nombre de CVE ; pour pdf, le
       .adoc est conservé si asciidoctor-pdf est absent)
    1  Aucun scanner n'a produit de résultat, ou --output manquant
''', '''
sbom_generator scan – Scan the CVEs of an SBOM file, with date filtering.

Usage:
  sbom-generator scan --sbom <file.cdx.json> [options]
  sbom-generator scan --image <image> [--per-layer] [options]
  sbom-generator scan --package <rpm|deb|tgz|zip|jar…> [--depth N] [options]

${parser.usage}

Examples:
  # All grype CVEs since 2024
  sbom-generator scan --sbom sbom.cdx.json --cve-after 2024-01-01

  # OSV-Scanner CVEs between two dates
  sbom-generator scan --sbom sbom.cdx.json --scanner osv \\
    --cve-after 2023-06-01 --cve-before 2024-01-01

  # All scanners, modification field, undated CVEs included
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --cve-date-field modified --cve-after 2023-01-01 --include-undated

  # SARIF export (GitHub Code Scanning) to a file
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --format sarif --output results.sarif

  # PDF summary report (Grype + OSV-Scanner + Trivy)
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --format pdf --output scan-report.pdf

  # Only actively exploited CVEs (CISA KEV), sorted by risk
  sbom-generator scan --sbom sbom.cdx.json --scanner all \\
    --only-kev --sort risk

  # Prioritise: CVEs with an EPSS exploitation probability ≥ 10 %
  sbom-generator scan --sbom sbom.cdx.json --epss-min 0.1

  # Offline: no network request (KEV/EPSS/PoC only via Grype + cache)
  sbom-generator scan --sbom sbom.cdx.json --no-enrich

  # CVEs per image layer (SBOM generated on the fly, one attributed scan)
  sbom-generator scan --image ./app.tar --per-layer --scanner all

  # Same, each layer SBOM scanned (layers computed in rootfs mode),
  # PDF report with an "Image layers" section
  sbom-generator scan --image nginx:latest --per-layer --layer-scan each \\
    --layer-mode rootfs --scanner all -f pdf -o nginx-layers.pdf

  # From a set already produced by sbom-generator --per-layer
  sbom-generator scan --sbom out/app.cdx.json --per-layer

  # Scan an RPM and the jars it contains directly (2 levels);
  # each CVE names the object (rpm, jar…) containing the vulnerable package
  sbom-generator scan --package app-1.0-1.x86_64.rpm --depth 2 --scanner all

  # Archive: everything it contains, with no depth limit
  sbom-generator scan --package release.tar.gz --depth all

Enrichment: each CVE is completed with CISA KEV (exploited in the wild),
EPSS (30-day exploitation probability), a public PoC signal and the CVSS
exploitability sub-score. On by default; --no-enrich (or SBOMGEN_OFFLINE=1)
turns it off, --no-poc only cuts the third-party source.

With --format markdown/asciidoc/pdf, each Critical (red) and High (orange)
CVE is also listed on stdout, one line per unique CVE (deduplicated across
scanners), with [KEV] / EPSS / [PoC] markers — handy during a build.
--color auto by default (colour if stdout is a terminal and NO_COLOR is
unset); --color always forces colour behind a pipe.

Exit codes:
  text / sarif:
    0  No CVE in the requested range
    1  At least one CVE found (or scanner error)
  markdown / asciidoc / pdf:
    0  Report produced (whatever the number of CVEs; for pdf, the
       .adoc is kept if asciidoctor-pdf is missing)
    1  No scanner produced any result, or --output missing
'''));
}

/// Convertit les résultats de scan (par scanner) en rapport SARIF 2.1.0,
/// consommable par exemple par `github/codeql-action/upload-sarif`.
Map<String, dynamic> _buildSarifReport(
  Map<String, List<Map<String, dynamic>>> resultsByScanner,
  String sbomFile,
  Map<String, ExploitInfo> exploitById,
) {
  final runs = <Map<String, dynamic>>[];

  for (final entry in resultsByScanner.entries) {
    final scanner = entry.key;
    final rulesById = <String, Map<String, dynamic>>{};
    final results = <Map<String, dynamic>>[];

    for (final v in entry.value) {
      final id = (v['id'] as String?) ?? '';
      if (id.isEmpty) continue;
      final severity = (v['severity'] as String?) ?? 'Unknown';
      final pkg = (v['package'] as String?) ?? '';
      final e = (v['exploit'] as ExploitInfo?) ??
          exploitById[_normalizeCveId(id)] ??
          ExploitInfo.empty;
      final exploitProps = <String, dynamic>{
        'kev': e.inKev,
        if (e.epssScore != null) 'epss': e.epssScore,
        if (e.epssPercentile != null) 'epssPercentile': e.epssPercentile,
        'poc': e.pocKnown,
        if (e.cvssExploitabilityScore != null)
          'cvssExploitability': e.cvssExploitabilityScore,
      };
      // KEV → priorité maximale dans GitHub Code Scanning.
      final score = e.inKev ? '9.5' : _sarifSecurityScore(severity);

      rulesById.putIfAbsent(
          id,
          () => {
                'id': id,
                'shortDescription': {
                  'text':
                      tr('$id — sévérité $severity', '$id — $severity severity')
                },
                'helpUri': 'https://osv.dev/vulnerability/$id',
                'properties': {
                  'security-severity': score,
                  ...exploitProps,
                },
              });

      final layer = v['layer'];
      results.add({
        'ruleId': id,
        'level': _sarifLevel(severity),
        'message': {
          'text': tr(
              'Paquet vulnérable : $pkg (sévérité $severity)'
                  '${layer != null ? ' — couche $layer' : ''}',
              'Vulnerable package: $pkg ($severity severity)'
                  '${layer != null ? ' — layer $layer' : ''}'),
        },
        'properties': {...exploitProps, if (layer != null) 'layer': layer},
        'locations': [
          {
            'physicalLocation': {
              'artifactLocation': {'uri': sbomFile.split('/').last},
            },
          }
        ],
      });
    }

    runs.add({
      'tool': {
        'driver': {
          'name': scanner,
          'informationUri': _scannerUrl(scanner),
          'rules': rulesById.values.toList(),
        },
      },
      'results': results,
    });
  }

  return {
    '\$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/'
        'master/Schemata/sarif-schema-2.1.0.json',
    'version': '2.1.0',
    'runs': runs,
  };
}

String _sarifLevel(String severity) => switch (severity.toUpperCase()) {
      'CRITICAL' || 'HIGH' => 'error',
      'MEDIUM' => 'warning',
      _ => 'note',
    };

String _sarifSecurityScore(String severity) => switch (severity.toUpperCase()) {
      'CRITICAL' => '9.0',
      'HIGH' => '7.0',
      'MEDIUM' => '4.0',
      'LOW' => '1.0',
      _ => '0.0',
    };

String _scannerUrl(String scanner) => switch (scanner) {
      'grype' => 'https://github.com/anchore/grype',
      'osv' => 'https://github.com/google/osv-scanner',
      'trivy' => 'https://github.com/aquasecurity/trivy',
      _ => '',
    };

/// Applique les overrides de licence par nom de paquet (`--license-map`).
List<Package> _applyLicenseOverrides(
    List<Package> packages, Map<String, String> overrides) {
  if (overrides.isEmpty) return packages;
  return [
    for (final pkg in packages)
      if (overrides[pkg.name] case final lic?)
        pkg.copyWith(license: lic)
      else
        pkg,
  ];
}

/// Renseigne le fournisseur des paquets qui n'en ont pas avec la valeur de
/// repli `--supplier` (utile quand la source — lockfile npm/Go/pip… — ne porte
/// aucune information d'éditeur).
List<Package> _applySupplierFallback(List<Package> packages, String supplier) {
  if (supplier.isEmpty) return packages;
  return [
    for (final pkg in packages)
      pkg.vendor.trim().isEmpty ? pkg.copyWith(vendor: supplier) : pkg,
  ];
}

// ── Sous-commande convert ─────────────────────────────────────────────────────

Future<void> _runConvert(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('input',
        abbr: 'i',
        mandatory: true,
        help: tr('Fichier SBOM source (CycloneDX JSON ou SPDX JSON/JSON-LD).',
            'Source SBOM file (CycloneDX JSON or SPDX JSON/JSON-LD).'))
    ..addOption('output',
        abbr: 'o',
        mandatory: true,
        help: tr(
            'Fichier de sortie. Avec plusieurs formats (-f a,b) : chemin de base.',
            'Output file. With several formats (-f a,b): base path.'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'cyclonedx',
        help: tr(
            'Format(s) cible(s), séparés par des virgules.\n'
                '  cyclonedx  spdx  spdx3  json  markdown  asciidoc  html  csv',
            'Target format(s), comma-separated.\n'
                '  cyclonedx  spdx  spdx3  json  markdown  asciidoc  html  csv'))
    ..addOption('name',
        abbr: 'n',
        help: tr(
            'Nom du document SBOM de sortie (remplace celui du fichier source).',
            'Name of the output SBOM document (replaces the source file\'s).'))
    ..addOption('supplier',
        help: tr(
            'Fournisseur par défaut des composants sans éditeur dans le SBOM\n'
                'source. N\'écrase jamais un fournisseur déjà présent.',
            'Default supplier for components with no vendor in the source\n'
                'SBOM. Never overrides an existing supplier.'))
    ..addOption(
      'cyclonedx-version',
      defaultsTo: '1.6',
      allowed: _validCycloneDxVersions,
      help: tr(
          'Version CycloneDX cible quand -f inclut "cyclonedx" (défaut : 1.6).',
          'Target CycloneDX version when -f includes "cyclonedx" (default: 1.6).'),
    )
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('convert: ${e.message}');
    _printConvertUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printConvertUsage(parser);
    exit(0);
  }

  final inputPath = args['input'] as String;
  final outputPath = args['output'] as String;
  final docName = args['name'] as String?;
  final cycloneDxVersion = args['cyclonedx-version'] as String;

  final formats = (args['format'] as String)
      .split(',')
      .map((f) => f.trim())
      .where((f) => f.isNotEmpty)
      .toList();
  for (final f in formats) {
    if (!_validFormats.contains(f)) {
      stderr.writeln(tr(
          'convert: format inconnu "$f". Valides : ${_validFormats.join(', ')}',
          'convert: unknown format "$f". Valid: ${_validFormats.join(', ')}'));
      exit(1);
    }
  }

  if (!await File(inputPath).exists()) {
    stderr.writeln(tr('convert: fichier introuvable : $inputPath',
        'convert: file not found: $inputPath'));
    exit(1);
  }

  final Map<String, dynamic> json;
  try {
    json = await SbomReader.loadJson(inputPath);
  } catch (e) {
    stderr.writeln(tr('convert: impossible de lire le JSON : $e',
        'convert: unable to read the JSON: $e'));
    exit(1);
  }

  final reader = SbomReader();
  final format = SbomReader.detectFormat(json);
  if (format == SbomFormat.unknown) {
    stderr.writeln(tr('convert: format SBOM non reconnu dans $inputPath',
        'convert: unrecognised SBOM format in $inputPath'));
    stderr.writeln(tr(
        '  Formats supportés : CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD',
        '  Supported formats: CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD'));
    exit(1);
  }

  List<Package> packages;
  try {
    packages = reader.read(json);
  } catch (e) {
    stderr.writeln(
        tr('convert: erreur de lecture : $e', 'convert: read error: $e'));
    exit(1);
  }

  final supplierFallback = (args['supplier'] as String?)?.trim() ?? '';
  if (supplierFallback.isNotEmpty) {
    packages = _applySupplierFallback(packages, supplierFallback);
  }

  final name = docName ?? reader.documentName(json);
  final formatLabel = switch (format) {
    SbomFormat.cyclonedx => 'CycloneDX',
    SbomFormat.spdx2 => 'SPDX 2.x',
    SbomFormat.spdx3 => 'SPDX 3.0',
    SbomFormat.unknown => '?',
  };
  print(tr(
      'Conversion : $inputPath ($formatLabel, ${packages.length} composant(s))',
      'Conversion: $inputPath ($formatLabel, ${packages.length} component(s))'));

  final outputBase = formats.length > 1 ? _basePath(outputPath) : null;
  for (final fmt in formats) {
    final outPath =
        outputBase != null ? '$outputBase${_formatExtension(fmt)}' : outputPath;
    try {
      switch (fmt) {
        case 'cyclonedx':
          await CycloneDxGenerator().writeToFile(packages, [], outPath,
              documentName: name, specVersion: cycloneDxVersion);
        case 'spdx':
          await SpdxGenerator()
              .writeToFile(packages, [], outPath, documentName: name);
        case 'spdx3':
          await Spdx3Generator()
              .writeToFile(packages, [], outPath, documentName: name);
        case 'json':
          await SimpleJsonGenerator()
              .writeToFile(packages, [], outPath, documentName: name);
        case 'markdown':
          await MarkdownGenerator()
              .writeToFile(packages, outPath, documentName: name);
        case 'asciidoc':
          await AsciidocGenerator()
              .writeToFile(packages, outPath, documentName: name);
        case 'html':
          await HtmlGenerator()
              .writeToFile(packages, outPath, documentName: name);
        case 'csv':
          await CsvGenerator()
              .writeToFile(packages, outPath, documentName: name);
      }
    } catch (e) {
      stderr.writeln(tr('convert: échec de l\'écriture ($fmt) : $e',
          'convert: write failed ($fmt): $e'));
      exit(1);
    }
    final sz = await File(outPath).length();
    print('→ $outPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
  }
}

void _printConvertUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator convert – Convertit un fichier SBOM vers un ou plusieurs formats.

Usage:
  sbom_generator convert -i source.cdx.json -f spdx -o output.spdx.json
  sbom_generator convert -i source.spdx.json -f cyclonedx,csv -o output

Formats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD
Formats cible supportés  : cyclonedx, spdx, spdx3, json, markdown, asciidoc, html, csv

${parser.usage}
''', '''
sbom_generator convert – Converts an SBOM file to one or more formats.

Usage:
  sbom_generator convert -i source.cdx.json -f spdx -o output.spdx.json
  sbom_generator convert -i source.spdx.json -f cyclonedx,csv -o output

Supported source formats: CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD
Supported target formats: cyclonedx, spdx, spdx3, json, markdown, asciidoc, html, csv

${parser.usage}
'''));
}

// ── Sous-commande licenses ─────────────────────────────────────────────────────

Future<void> _runLicenses(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('input',
        abbr: 'i',
        mandatory: true,
        help: tr('Fichier SBOM source (CycloneDX JSON ou SPDX JSON/JSON-LD).',
            'Source SBOM file (CycloneDX JSON or SPDX JSON/JSON-LD).'))
    ..addOption('output',
        abbr: 'o',
        help: tr(
            'Fichier de sortie (ex : licences.adoc). Facultatif avec '
                '--format json (sortie standard).',
            'Output file (e.g. licences.adoc). Optional with '
                '--format json (standard output).'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'asciidoc',
        allowed: ['asciidoc', 'adoc', 'markdown', 'html', 'csv', 'json'],
        help: tr('Format du rapport.', 'Report format.'))
    ..addOption('name',
        abbr: 'n',
        help: tr('Nom du document (remplace celui du fichier source).',
            'Document name (replaces the source file\'s).'))
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('licenses: ${e.message}');
    _printLicensesUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printLicensesUsage(parser);
    exit(0);
  }

  final inputPath = args['input'] as String;
  final outputPath = args['output'] as String?;
  final docName = args['name'] as String?;
  final format = LicenseReportFormat.parse(args['format'] as String)!;

  if (outputPath == null && format != LicenseReportFormat.json) {
    stderr.writeln(tr(
        'licenses: --output est obligatoire (sauf avec --format json).',
        'licenses: --output is required (except with --format json).'));
    exit(1);
  }

  if (!await File(inputPath).exists()) {
    stderr.writeln(tr('licenses: fichier introuvable : $inputPath',
        'licenses: file not found: $inputPath'));
    exit(1);
  }

  final Map<String, dynamic> json;
  try {
    json = await SbomReader.loadJson(inputPath);
  } catch (e) {
    stderr.writeln(tr('licenses: impossible de lire le JSON : $e',
        'licenses: unable to read the JSON: $e'));
    exit(1);
  }

  final reader = SbomReader();
  final sbomFormat = SbomReader.detectFormat(json);
  if (sbomFormat == SbomFormat.unknown) {
    stderr.writeln(tr('licenses: format SBOM non reconnu dans $inputPath',
        'licenses: unrecognised SBOM format in $inputPath'));
    stderr.writeln(tr(
        '  Formats supportés : CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD',
        '  Supported formats: CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD'));
    exit(1);
  }

  final List<Package> packages;
  try {
    packages = reader.read(json);
  } catch (e) {
    stderr.writeln(
        tr('licenses: erreur de lecture : $e', 'licenses: read error: $e'));
    exit(1);
  }

  final name = docName ?? reader.documentName(json);
  final generator = LicenseReportGenerator();
  if (outputPath == null) {
    // JSON sur la sortie standard, sans message parasite.
    stdout.writeln(
        generator.render(packages, documentName: name, format: format));
    return;
  }
  print(tr('Rapport de licences : $inputPath (${packages.length} composant(s))',
      'License report: $inputPath (${packages.length} component(s))'));

  try {
    await generator.writeToFile(packages, outputPath,
        documentName: name, format: format);
  } catch (e) {
    stderr.writeln(tr(
        'licenses: échec de l\'écriture : $e', 'licenses: write failed: $e'));
    exit(1);
  }

  final sz = await File(outputPath).length();
  print('→ $outputPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
}

void _printLicensesUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator licenses – Génère un rapport de licences à partir d'un fichier SBOM
(AsciiDoc par défaut ; Markdown, HTML, CSV ou JSON avec --format).

Le rapport regroupe les paquets par licence, avec un résumé et des
avertissements pour les licences copyleft (GPL/AGPL/LGPL/MPL/EPL/CDDL/CPL/EUPL)
et les paquets sans licence détectée.

Usage:
  sbom_generator licenses -i sbom.cdx.json -o licences.adoc
  sbom_generator licenses -i sbom.spdx.json -o licences.adoc -n "Mon projet"
  sbom_generator licenses -i sbom.cdx.json -f html -o licences.html
  sbom_generator licenses -i sbom.cdx.json -f json        # JSON sur stdout

Formats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD

${parser.usage}
''', '''
sbom_generator licenses – Generates a license report from an SBOM file
(AsciiDoc by default; Markdown, HTML, CSV or JSON with --format).

The report groups packages by license, with a summary and warnings for
copyleft licenses (GPL/AGPL/LGPL/MPL/EPL/CDDL/CPL/EUPL) and for packages
with no detected license.

Usage:
  sbom_generator licenses -i sbom.cdx.json -o licences.adoc
  sbom_generator licenses -i sbom.spdx.json -o licences.adoc -n "My project"
  sbom_generator licenses -i sbom.cdx.json -f html -o licences.html
  sbom_generator licenses -i sbom.cdx.json -f json        # JSON on stdout

Supported source formats: CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD

${parser.usage}
'''));
}

// ── Sous-commande cra ─────────────────────────────────────────────────────────

Future<void> _runCra(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('sbom',
        abbr: 's',
        mandatory: true,
        help: tr('Fichier SBOM à évaluer (CycloneDX JSON ou SPDX JSON).',
            'SBOM file to assess (CycloneDX JSON or SPDX JSON).'))
    ..addOption('config',
        abbr: 'c',
        help: tr(
            'Fichier de métadonnées fabricant/produit (clé: valeur par '
                'ligne). Défaut : ./cra.yaml s\'il existe.',
            'Manufacturer/product metadata file (key: value per '
                'line). Default: ./cra.yaml if it exists.'))
    ..addOption('manufacturer',
        help: tr('Nom du fabricant (surcharge --config).',
            'Manufacturer name (overrides --config).'))
    ..addOption('product', help: tr('Nom du produit.', 'Product name.'))
    ..addOption('product-version',
        help: tr('Version du produit.', 'Product version.'))
    ..addOption('support-until',
        help: tr('Date de fin de support (AAAA-MM-JJ).',
            'End-of-support date (YYYY-MM-DD).'))
    ..addOption('vuln-contact',
        help: tr('Adresse (e-mail ou URL) de signalement des vulnérabilités.',
            'Address (e-mail or URL) for reporting vulnerabilities.'))
    ..addOption('cvd-policy-url',
        help: tr('URL de la politique de divulgation coordonnée.',
            'URL of the coordinated vulnerability disclosure policy.'))
    ..addFlag('scan',
        defaultsTo: true,
        help: tr(
            'Lancer une analyse de vulnérabilités (grype/osv/trivy) pour '
                'évaluer l\'inventaire et les correctifs. --no-scan pour s\'en '
                'passer.',
            'Run a vulnerability scan (grype/osv/trivy) to assess the '
                'inventory and the fixes. --no-scan to skip it.'))
    ..addOption('scanner',
        abbr: 'S',
        defaultsTo: 'grype',
        help: tr('Scanner(s) : grype (défaut), osv, trivy, all.',
            'Scanner(s): grype (default), osv, trivy, all.'))
    ..addFlag('enrich',
        defaultsTo: true,
        help: tr(
            'Enrichir les CVE (CISA KEV / EPSS). --no-enrich pour rester '
                'hors-ligne.',
            'Enrich CVEs (CISA KEV / EPSS). --no-enrich to stay '
                'offline.'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'pdf',
        allowed: ['pdf', 'asciidoc', 'json'],
        help: tr('Format de sortie : pdf (défaut), asciidoc, json.',
            'Output format: pdf (default), asciidoc, json.'))
    ..addOption('output',
        abbr: 'o',
        help: tr(
            'Fichier de sortie. Requis pour pdf/asciidoc ; json sur stdout '
                'si omis.',
            'Output file. Required for pdf/asciidoc; json on stdout '
                'if omitted.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('cra: ${e.message}');
    _printCraUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printCraUsage(parser);
    exit(0);
  }

  final sbomFile = args['sbom'] as String;
  final format = args['format'] as String;
  final outputPath = args['output'] as String?;
  final doScan = args['scan'] as bool;

  if (!await File(sbomFile).exists()) {
    stderr.writeln(tr('cra: fichier SBOM introuvable : $sbomFile',
        'cra: SBOM file not found: $sbomFile'));
    exit(1);
  }
  if ((format == 'pdf' || format == 'asciidoc') && outputPath == null) {
    stderr.writeln(tr(
        'cra: --output <fichier> est requis pour --format $format.',
        'cra: --output <file> is required for --format $format.'));
    exit(1);
  }

  final Map<String, dynamic> sbomJson;
  try {
    sbomJson = await SbomReader.loadJson(sbomFile);
  } catch (e) {
    stderr.writeln(tr('cra: impossible de lire le SBOM : $e',
        'cra: unable to read the SBOM: $e'));
    exit(1);
  }
  if (SbomReader.detectFormat(sbomJson) == SbomFormat.unknown) {
    stderr.writeln(tr(
        'cra: format SBOM non reconnu (CycloneDX / SPDX attendu).',
        'cra: unrecognised SBOM format (CycloneDX / SPDX expected).'));
    exit(1);
  }

  // Métadonnées : cra.yaml (ou ./cra.yaml par défaut) puis surcharge CLI.
  var meta = const CraMetadata();
  final configPath = args['config'] as String? ??
      (await File('cra.yaml').exists() ? 'cra.yaml' : null);
  if (configPath != null) {
    if (!await File(configPath).exists()) {
      stderr.writeln(tr('cra: fichier de config introuvable : $configPath',
          'cra: config file not found: $configPath'));
      exit(1);
    }
    meta = CraMetadata.parseConfig(await File(configPath).readAsString());
  }
  final cli = CraMetadata(
    manufacturer: args['manufacturer'] as String?,
    product: args['product'] as String?,
    productVersion: args['product-version'] as String?,
    supportUntil: args['support-until'] as String?,
    vulnerabilityContact: args['vuln-contact'] as String?,
    cvdPolicyUrl: args['cvd-policy-url'] as String?,
  );
  meta = cli.merge(meta);

  // Analyse de vulnérabilités (optionnelle).
  Map<String, List<Map<String, dynamic>>>? scanResults;
  var exploitById = <String, ExploitInfo>{};
  final toolVersions = <String, String?>{};
  if (doScan) {
    final scanner = args['scanner'] as String;
    final scanners = scanner == 'all' ? ['grype', 'osv', 'trivy'] : [scanner];
    scanResults = {};
    for (final s in scanners) {
      final vulns = await _runScanner(s, sbomFile, quiet: true);
      if (vulns == null) continue;
      scanResults[s] = vulns;
      toolVersions[{
        'grype': 'Grype',
        'osv': 'OSV-Scanner',
        'trivy': 'Trivy'
      }[s]!] = await _scannerVersion(s) ?? tr('inconnue', 'unknown');
    }
    if (scanResults.isEmpty) {
      stderr.writeln(tr(
          'cra: aucun scanner disponible — rapport produit sans '
              'inventaire de vulnérabilités (utilisez --no-scan pour l\'assumer).',
          'cra: no scanner available — report produced without '
              'a vulnerability inventory (use --no-scan to accept this).'));
      scanResults = null;
    } else {
      exploitById = await _enrichFindings(
        scanResults,
        enrich: args['enrich'] as bool,
        poc: false,
        timeoutSeconds: 8,
        quiet: true,
      );
    }
  }

  // Score sbomqs (best-effort).
  String? sbomqsOut;
  try {
    final r = await Process.run('sbomqs', ['score', '--basic', sbomFile]);
    if (r.exitCode == 0) sbomqsOut = (r.stdout as String).trim();
  } catch (_) {}

  final gen = CraReportGenerator(
    sbomPath: sbomFile,
    sbom: sbomJson,
    meta: meta,
    scanResults: scanResults,
    exploitById: exploitById,
    toolVersions: toolVersions,
    sbomqsOutput: sbomqsOut,
  );

  if (format == 'json') {
    final s = gen.toJsonString();
    if (outputPath != null) {
      await File(outputPath).writeAsString('$s\n');
      stdout.writeln(tr('Rapport CRA (JSON) écrit → $outputPath',
          'CRA report (JSON) written → $outputPath'));
    } else {
      print(s);
    }
    exit(gen.verdict == CraStatus.fail ? 2 : 0);
  }

  final adocPath = format == 'asciidoc'
      ? outputPath!
      : (outputPath!.toLowerCase().endsWith('.pdf')
          ? '${outputPath.substring(0, outputPath.length - 4)}.adoc'
          : '$outputPath.adoc');
  await File(adocPath).writeAsString(gen.toAsciiDoc());

  if (format == 'asciidoc') {
    stdout.writeln(tr('Rapport CRA (AsciiDoc) écrit → $adocPath',
        'CRA report (AsciiDoc) written → $adocPath'));
  } else {
    try {
      final r = await renderAsciiDocToPdf(adocPath, outputPath);
      if (r.exitCode == 0) {
        stdout.writeln(tr('Rapport CRA (PDF) écrit → $outputPath',
            'CRA report (PDF) written → $outputPath'));
      } else {
        stderr.writeln(tr(
            'cra: asciidoctor-pdf a échoué (code ${r.exitCode}) — '
                'AsciiDoc conservé → $adocPath',
            'cra: asciidoctor-pdf failed (code ${r.exitCode}) — '
                'AsciiDoc kept → $adocPath'));
      }
    } on ProcessException {
      stderr.writeln(tr(
          'cra: asciidoctor-pdf introuvable — PDF non généré, '
              'AsciiDoc conservé → $adocPath',
          'cra: asciidoctor-pdf not found — PDF not generated, '
              'AsciiDoc kept → $adocPath'));
    }
  }

  final v = gen.verdict;
  stdout.writeln(
      tr('Verdict (périmètre vérifié) : ', 'Verdict (verified scope): ') +
          switch (v) {
            CraStatus.ok => tr('conforme', 'compliant'),
            CraStatus.partial =>
              tr('conforme avec réserves', 'compliant with reservations'),
            CraStatus.fail => tr(
                'NON conforme (${gen.blockers.length} point(s) bloquant(s))',
                'NON-compliant (${gen.blockers.length} blocking item(s))'),
            CraStatus.na => tr('non évalué', 'not assessed'),
          });
  exit(v == CraStatus.fail ? 2 : 0);
}

void _printCraUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator cra – Rapport de conformité Cyber Resilience Act (UE 2024/2847).

Périmètre : éléments vérifiables automatiquement uniquement — format et
complétude du SBOM (Annexe I §2 point 1, BSI TR-03183-2, éléments minimaux
NTIA), inventaire des vulnérabilités connues et disponibilité des correctifs
(Annexe I §2 points 1-2), vulnérabilités activement exploitées (art. 14).
Les autres obligations du CRA relèvent du fabricant. Ce rapport n'est pas une
déclaration de conformité.

Usage:
  sbom-generator cra --sbom sbom.cdx.json --format pdf -o rapport-cra.pdf
  sbom-generator cra --sbom sbom.cdx.json --config cra.yaml -o rapport-cra.pdf
  sbom-generator cra --sbom sbom.cdx.json --no-scan --format json

Fichier cra.yaml (toutes les clés sont facultatives) :
  manufacturer: "ACME Corp"
  product: "WidgetOS"
  product_version: "3.2.1"
  support_until: "2030-12-31"
  vulnerability_contact: "security@acme.example"
  cvd_policy_url: "https://acme.example/security/policy"

${parser.usage}

Codes de retour : 0 = conforme / conforme avec réserves, 2 = non conforme
(au moins un point bloquant sur le périmètre vérifié).
''', '''
sbom_generator cra – Cyber Resilience Act compliance report (EU 2024/2847).

Scope: only automatically verifiable items — SBOM format and completeness
(Annex I §2 point 1, BSI TR-03183-2, NTIA minimum elements), inventory of
known vulnerabilities and availability of fixes (Annex I §2 points 1-2),
actively exploited vulnerabilities (art. 14). The other CRA obligations
remain the manufacturer's responsibility. This report is not a declaration
of conformity.

Usage:
  sbom-generator cra --sbom sbom.cdx.json --format pdf -o cra-report.pdf
  sbom-generator cra --sbom sbom.cdx.json --config cra.yaml -o cra-report.pdf
  sbom-generator cra --sbom sbom.cdx.json --no-scan --format json

cra.yaml file (all keys are optional):
  manufacturer: "ACME Corp"
  product: "WidgetOS"
  product_version: "3.2.1"
  support_until: "2030-12-31"
  vulnerability_contact: "security@acme.example"
  cvd_policy_url: "https://acme.example/security/policy"

${parser.usage}

Exit codes: 0 = compliant / compliant with reservations, 2 = non-compliant
(at least one blocking item within the verified scope).
'''));
}

// ── Sous-commande validate ────────────────────────────────────────────────────

Future<void> _runValidate(List<String> arguments) async {
  final parser = ArgParser()
    ..addFlag('strict',
        defaultsTo: false,
        negatable: false,
        help: tr(
            'En mode strict, les champs recommandés (mais non obligatoires) '
                'génèrent aussi des erreurs.',
            'In strict mode, recommended (but not mandatory) fields '
                'also raise errors.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.', 'Help.'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('validate: ${e.message}');
    _printValidateUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printValidateUsage(parser);
    exit(0);
  }

  final files = args.rest;
  if (files.isEmpty) {
    stderr.writeln(tr('validate: au moins un fichier SBOM requis.',
        'validate: at least one SBOM file is required.'));
    _printValidateUsage(parser);
    exit(1);
  }

  final strict = args['strict'] as bool;
  int totalErrors = 0;

  for (final path in files) {
    if (!await File(path).exists()) {
      print(tr('$path : ERREUR — fichier introuvable',
          '$path : ERROR — file not found'));
      totalErrors++;
      continue;
    }

    final Map<String, dynamic> json;
    try {
      json = await SbomReader.loadJson(path);
    } catch (e) {
      print(tr('$path : ERREUR — JSON invalide : $e',
          '$path : ERROR — invalid JSON: $e'));
      totalErrors++;
      continue;
    }

    final errors = _validateSbom(json, strict: strict);
    final format = SbomReader.detectFormat(json);
    final label = switch (format) {
      SbomFormat.cyclonedx => 'CycloneDX ${json['specVersion'] ?? ''}',
      SbomFormat.spdx2 => 'SPDX ${json['spdxVersion'] ?? ''}',
      SbomFormat.spdx3 => 'SPDX 3.0 JSON-LD',
      SbomFormat.unknown => tr('format inconnu', 'unknown format'),
    };

    if (errors.isEmpty) {
      print('$path : OK ($label)');
    } else {
      print(tr('$path : $label — ${errors.length} erreur(s) :',
          '$path : $label — ${errors.length} error(s):'));
      for (final e in errors) {
        print('  ✗ $e');
      }
      totalErrors += errors.length;
    }
  }

  exit(totalErrors == 0 ? 0 : 1);
}

/// Returns a list of validation error messages for [json].
List<String> _validateSbom(Map<String, dynamic> json, {bool strict = false}) {
  final errors = <String>[];
  final format = SbomReader.detectFormat(json);

  switch (format) {
    case SbomFormat.cyclonedx:
      _validateCycloneDx(json, errors, strict: strict);
    case SbomFormat.spdx2:
      _validateSpdx2(json, errors, strict: strict);
    case SbomFormat.spdx3:
      _validateSpdx3(json, errors, strict: strict);
    case SbomFormat.unknown:
      errors.add(tr(
          'Aucun indicateur de format reconnu. '
              'Attendu : bomFormat="CycloneDX", spdxVersion ou @context/@graph.',
          'No recognised format indicator. '
              'Expected: bomFormat="CycloneDX", spdxVersion or @context/@graph.'));
  }
  return errors;
}

void _validateCycloneDx(Map<String, dynamic> json, List<String> errors,
    {bool strict = false}) {
  if (json['bomFormat'] != 'CycloneDX') {
    errors.add(
        tr('bomFormat doit être "CycloneDX"', 'bomFormat must be "CycloneDX"'));
  }
  if (json['specVersion'] == null) {
    errors.add(tr('specVersion manquant', 'specVersion missing'));
  }
  if (json['version'] == null && strict) {
    errors.add(tr('[strict] version manquant', '[strict] version missing'));
  }
  if (json['serialNumber'] == null && strict) {
    errors.add(
        tr('[strict] serialNumber manquant', '[strict] serialNumber missing'));
  }

  final components = json['components'];
  if (components != null && components is! List) {
    errors.add(tr('components doit être un tableau JSON',
        'components must be a JSON array'));
  } else if (components is List) {
    for (int i = 0; i < components.length; i++) {
      final c = components[i];
      if (c is! Map) continue;
      if (c['name'] == null || (c['name'] as String).isEmpty) {
        errors.add(tr('composant[$i] : champ name manquant ou vide',
            'component[$i]: name field missing or empty'));
      }
      if (c['type'] == null) {
        errors.add(tr(
            'composant[$i] (${c['name'] ?? '?'}) : champ type manquant',
            'component[$i] (${c['name'] ?? '?'}): type field missing'));
      }
      if (strict && c['version'] == null) {
        errors.add(tr(
            '[strict] composant[$i] (${c['name'] ?? '?'}) : version manquante',
            '[strict] component[$i] (${c['name'] ?? '?'}): version missing'));
      }
    }
  }
}

void _validateSpdx2(Map<String, dynamic> json, List<String> errors,
    {bool strict = false}) {
  final ver = json['spdxVersion'] as String?;
  if (ver == null || !ver.startsWith('SPDX-')) {
    errors.add(tr('spdxVersion manquant ou invalide (attendu : SPDX-2.x)',
        'spdxVersion missing or invalid (expected: SPDX-2.x)'));
  }
  if (json['SPDXID'] != 'SPDXRef-DOCUMENT') {
    errors.add(tr('SPDXID doit être "SPDXRef-DOCUMENT"',
        'SPDXID must be "SPDXRef-DOCUMENT"'));
  }
  if (json['name'] == null) errors.add(tr('name manquant', 'name missing'));
  if (json['dataLicense'] == null) {
    errors.add(tr('dataLicense manquant', 'dataLicense missing'));
  }
  if (strict && json['creationInfo'] == null) {
    errors.add(
        tr('[strict] creationInfo manquant', '[strict] creationInfo missing'));
  }

  final packages = json['packages'];
  if (packages is List) {
    for (int i = 0; i < packages.length; i++) {
      final p = packages[i] as Map?;
      if (p == null) continue;
      if (p['SPDXID'] == null) {
        errors.add(tr(
            'packages[$i] : SPDXID manquant', 'packages[$i]: SPDXID missing'));
      }
      if (p['name'] == null) {
        errors.add(
            tr('packages[$i] : name manquant', 'packages[$i]: name missing'));
      }
      if (p['versionInfo'] == null && strict) {
        errors.add(tr(
            '[strict] packages[$i] (${p['name'] ?? '?'}) : versionInfo manquant',
            '[strict] packages[$i] (${p['name'] ?? '?'}): versionInfo missing'));
      }
    }
  }
}

void _validateSpdx3(Map<String, dynamic> json, List<String> errors,
    {bool strict = false}) {
  if (json['@context'] == null) {
    errors.add(tr('@context manquant', '@context missing'));
  }
  final graph = json['@graph'];
  if (graph == null) {
    errors.add(tr('@graph manquant', '@graph missing'));
    return;
  }
  if (graph is! List) {
    errors.add(
        tr('@graph doit être un tableau JSON', '@graph must be a JSON array'));
    return;
  }
  final hasDoc = graph.any(
      (node) => node is Map && (node['type'] as String?) == 'SpdxDocument');
  if (!hasDoc) {
    errors.add(tr('@graph ne contient pas d\'élément SpdxDocument',
        '@graph contains no SpdxDocument element'));
  }
  for (int i = 0; i < graph.length; i++) {
    final node = graph[i] as Map?;
    if (node == null) continue;
    if (node['spdxId'] == null && strict) {
      errors.add(tr('[strict] @graph[$i] : spdxId manquant',
          '[strict] @graph[$i]: spdxId missing'));
    }
  }
}

void _printValidateUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator validate – Vérifie la structure d'un ou plusieurs fichiers SBOM.

Usage:
  sbom_generator validate <fichier1.cdx.json> [fichier2.spdx.json ...]

Formats supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD

${parser.usage}

Codes de retour:
  0  Tous les fichiers sont valides
  1  Au moins un fichier est invalide ou introuvable
''', '''
sbom_generator validate – Checks the structure of one or more SBOM files.

Usage:
  sbom_generator validate <file1.cdx.json> [file2.spdx.json ...]

Supported formats: CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD

${parser.usage}

Exit codes:
  0  All files are valid
  1  At least one file is invalid or not found
'''));
}

void _printUsage(ArgParser parser) {
  stdout.writeln(tr('''
sbom_generator – Génère un SBOM à partir d'une liste de paquets ou d'une image de conteneur OCI.

Usage:
  dart run bin/sbom_generator.dart --input <file> [options]
  dart run bin/sbom_generator.dart --image <ref>  [options]
  dart run bin/sbom_generator.dart --image <ref> --input <file> [options]
  dart run bin/sbom_generator.dart --binary <fichier> [options]

${parser.usage}

Format du fichier d'entrée (--input) :
  Une référence de paquet par ligne. Les lignes commençant par # sont ignorées.
  Les références peuvent être mélangées :
    • RPM : nom de paquet installé/NEVRA, ou chemin vers un fichier .rpm
    • Wheel Python : chemin vers un fichier .whl
    • Archive source : chemin vers un .tar, .tar.gz ou .tgz
        - sdist Python (PKG-INFO présent) → PURL pkg:pypi/…
        - Archive générique (sans métadonnées) → PURL pkg:generic/…
    • Debian : chemin vers un fichier .deb
    • requirements.txt : chemin vers un fichier de dépendances pip
    • Manifestes/lockfiles : go.sum, go.mod, package-lock.json, yarn.lock,
      pom.xml, pubspec.lock, pubspec.yaml

Formats d'image OCI (--image) :
    • Registre  : nginx:latest  ubuntu:22.04  myregistry.io/app@sha256:…
    • Archive   : /chemin/image.tar        (docker save / skopeo docker-archive)
    • OCI layout: /chemin/vers/oci_dir/    (dossier contenant index.json)

Examples:
  # CycloneDX depuis une image Docker Hub (via syft, défaut)
  dart run bin/sbom_generator.dart --image nginx:latest -o nginx.cdx.json

  # SPDX 2.3 depuis une archive tar, backend trivy
  dart run bin/sbom_generator.dart --image ./ubuntu.tar --oci-tool trivy -f spdx -o sbom.spdx.json

  # OCI layout directory, backend skopeo
  dart run bin/sbom_generator.dart --image ./oci_layout/ --oci-tool skopeo -o sbom.cdx.json

  # CycloneDX depuis une image Docker Hub, backend cdxgen
  dart run bin/sbom_generator.dart --image nginx:latest --oci-tool cdxgen -o nginx.cdx.json

  # Un SBOM par couche de l'image (delta), en plus du global
  dart run bin/sbom_generator.dart --image ./app.tar --per-layer -o out/app
  dart run bin/sbom_generator.dart --image ./app.tar --per-layer --layer-mode rootfs -o out/app

  # Combiner image OCI + liste de paquets supplémentaires
  dart run bin/sbom_generator.dart --image nginx:latest -i extra_pkgs.txt -o sbom.cdx.json

  # Multi-format en un seul passage
  dart run bin/sbom_generator.dart --image nginx:latest -f cyclonedx,spdx,markdown -o sbom

  # Depuis un fichier de paquets (mode classique)
  dart run bin/sbom_generator.dart -i packages.txt -o sbom.cdx.json

  # Binaire lié statiquement (ex. exécutable Go) — dépendances embarquées
  # lues via syft (buildinfo Go / classifieur générique), sans dépôt/registre
  dart run bin/sbom_generator.dart --binary /usr/local/bin/mon-app -o app.cdx.json
''', '''
sbom_generator – Generate an SBOM from a list of packages or an OCI container image.

Usage:
  dart run bin/sbom_generator.dart --input <file> [options]
  dart run bin/sbom_generator.dart --image <ref>  [options]
  dart run bin/sbom_generator.dart --image <ref> --input <file> [options]
  dart run bin/sbom_generator.dart --binary <file> [options]

${parser.usage}

Input file format (--input):
  One package reference per line. Lines starting with # are ignored.
  References can be mixed:
    • RPM: installed package name/NEVRA, or path to a .rpm file
    • Python wheel: path to a .whl file
    • Source archive: path to a .tar, .tar.gz or .tgz file
        - Python sdist (PKG-INFO present) → PURL pkg:pypi/…
        - Generic archive (no metadata)   → PURL pkg:generic/…
    • Debian: path to a .deb file
    • requirements.txt: path to a pip requirements file
    • Manifests/lockfiles: go.sum, go.mod, package-lock.json, yarn.lock,
      pom.xml, pubspec.lock, pubspec.yaml

OCI image formats (--image):
    • Registry  : nginx:latest  ubuntu:22.04  myregistry.io/app@sha256:…
    • Archive   : /path/image.tar          (docker save / skopeo docker-archive)
    • OCI layout: /path/to/oci_dir/        (directory containing index.json)

Examples:
  # CycloneDX from a Docker Hub image (via syft, default)
  dart run bin/sbom_generator.dart --image nginx:latest -o nginx.cdx.json

  # SPDX 2.3 from a tar archive, trivy backend
  dart run bin/sbom_generator.dart --image ./ubuntu.tar --oci-tool trivy -f spdx -o sbom.spdx.json

  # OCI layout directory, skopeo backend
  dart run bin/sbom_generator.dart --image ./oci_layout/ --oci-tool skopeo -o sbom.cdx.json

  # CycloneDX from a Docker Hub image, cdxgen backend
  dart run bin/sbom_generator.dart --image nginx:latest --oci-tool cdxgen -o nginx.cdx.json

  # One SBOM per image layer (delta), in addition to the global one
  dart run bin/sbom_generator.dart --image ./app.tar --per-layer -o out/app
  dart run bin/sbom_generator.dart --image ./app.tar --per-layer --layer-mode rootfs -o out/app

  # Combine an OCI image + a list of extra packages
  dart run bin/sbom_generator.dart --image nginx:latest -i extra_pkgs.txt -o sbom.cdx.json

  # Multi-format in a single pass
  dart run bin/sbom_generator.dart --image nginx:latest -f cyclonedx,spdx,markdown -o sbom

  # From a package list file (classic mode)
  dart run bin/sbom_generator.dart -i packages.txt -o sbom.cdx.json

  # Statically linked binary (e.g. Go executable) — embedded dependencies
  # read via syft (Go buildinfo / generic classifier), no repository/registry
  dart run bin/sbom_generator.dart --binary /usr/local/bin/my-app -o app.cdx.json
'''));
}
