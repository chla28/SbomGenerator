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
import 'package:sbom_generator/signature.dart';
import 'package:sbom_generator/watch.dart';
import 'package:sbom_generator/spdx3_generator.dart';
import 'package:sbom_generator/spdx3_view.dart';
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
import 'package:sbom_generator/cargo_parser.dart';
import 'package:sbom_generator/composer_parser.dart';
import 'package:sbom_generator/gem_parser.dart';
import 'package:sbom_generator/pnpm_parser.dart';
import 'package:sbom_generator/maven_parser.dart';
import 'package:sbom_generator/pubspec_parser.dart';
import 'package:sbom_generator/csv_generator.dart';
import 'package:sbom_generator/sbom_reader.dart';
import 'package:sbom_generator/scan_report_generator.dart';
import 'package:sbom_generator/license_report_generator.dart';
import 'package:sbom_generator/vuln_enrichment.dart';
import 'package:sbom_generator/cra_report.dart';
import 'package:sbom_generator/i18n.dart';
import 'package:sbom_generator/tool_runner.dart';
import 'package:sbom_generator/schema_validator.dart';
import 'package:sbom_generator/vex.dart';
import 'package:sbom_generator/scan_policy.dart';
import 'package:sbom_generator/report_input.dart';

const _version = '1.10.8';

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
const _validScanFormats = {
  'text',
  'json',
  'sarif',
  'markdown',
  'asciidoc',
  'pdf'
};
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

  // Sous-commande `report` : rapport de vulnérabilités depuis un fichier
  if (arguments.isNotEmpty && arguments.first == 'report') {
    await _runReport(arguments.sublist(1));
    return;
  }

  // Sous-commande `vex` : crée / complète un document VEX
  if (arguments.isNotEmpty && arguments.first == 'vex') {
    await _runVex(arguments.sublist(1));
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

  // Sous-commande `watch` : rescanne des SBOM et signale les nouvelles CVE
  if (arguments.isNotEmpty && arguments.first == 'watch') {
    await _runWatch(arguments.sublist(1));
    return;
  }

  // Sous-commande `verify` : vérifie la signature cosign d'un SBOM
  if (arguments.isNotEmpty && arguments.first == 'verify') {
    await _runVerify(arguments.sublist(1));
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

  if (_wantsJsonLog(arguments)) {
    _jsonLog = true;
    await runZoned(() => _runGenerate(arguments),
        zoneSpecification: ZoneSpecification(print: (self, parent, zone, line) {
      final out = _jsonLogLine(line);
      if (out != null) parent.print(zone, out);
    }));
    return;
  }
  await _runGenerate(arguments);
}

/// `true` quand `--log-format json` (ou `=json`) figure dans [args].
bool _wantsJsonLog(List<String> args) {
  for (var i = 0; i < args.length; i++) {
    if (args[i] == '--log-format=json') return true;
    if (args[i] == '--log-format' &&
        i + 1 < args.length &&
        args[i + 1] == 'json') {
      return true;
    }
  }
  return false;
}

/// Mode `--log-format json` : stdout ne porte que des événements JSON, un par
/// ligne (NDJSON) — `output`, `progress`, `log`.
bool _jsonLog = false;

final _writtenRe = RegExp(r'^SBOM written → (.+?)  \(([\d.]+) KB\)$');

/// Convertit une ligne imprimée en événement JSON ; `null` pour l'ignorer.
String? _jsonLogLine(String line) {
  if (line.startsWith('{"event":')) return line;
  final m = _writtenRe.firstMatch(line);
  if (m != null) {
    return jsonEncode({
      'event': 'output',
      'path': m.group(1),
      'kb': double.parse(m.group(2)!),
    });
  }
  if (line.trim().isEmpty) return null;
  return jsonEncode({'event': 'log', 'message': line});
}

Future<void> _runGenerate(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption(
      'input',
      abbr: 'i',
      help: tr('Fichier d\'entrée contenant une référence de paquet par ligne, un\nfichier archive/paquet unique, ou un dossier à parcourir\nrécursivement. Chaque ligne (ou fichier découvert) peut être :\n  • un nom de paquet RPM, un NEVRA ou un chemin vers un .rpm\n  • un chemin vers un paquet Debian .deb\n  • un chemin vers une wheel Python .whl\n  • un chemin vers un fichier requirements.txt\n  • un chemin vers une archive .tar / .tar.gz / .tgz / .zip\n  • un chemin vers un .jar (coordonnées Maven via\n    META-INF/maven/*/*/pom.properties, ou convention de nom)\n  • un chemin vers un fichier go.sum ou go.mod\n  • un chemin vers un package-lock.json ou un yarn.lock\n  • un chemin vers un fichier pom.xml\n  • un chemin vers un pubspec.lock ou un pubspec.yaml\n  • un chemin vers un Cargo.lock, un pnpm-lock.yaml, un composer.lock\n    ou un Gemfile.lock\nSi --input est un dossier, tous les types de fichiers ci-dessus\ny sont recherchés récursivement (unzip requis pour les .jar).\nFacultatif si --image est fourni.'),
    )
    ..addOption(
      'image',
      abbr: 'I',
      help: tr('Image de conteneur OCI à analyser.\nFormats acceptés :\n  • Registre  : nginx:latest  ubuntu@sha256:…\n  • Archive   : /chemin/image.tar  (docker save)\n  • OCI layout: /chemin/vers/oci_dir/  (index.json présent)\nÀ combiner avec --oci-tool pour choisir le backend.\nUn chemin de fichier local (binaire) fonctionne aussi via le\nbackend syft — voir --binary, plus explicite pour ce cas.'),
    )
    ..addOption(
      'binary',
      abbr: 'b',
      help: tr('Binaire local à analyser directement (ex. exécutable Go lié\nstatiquement) — alias explicite pour --image <fichier>.\nForce --oci-tool syft : seul backend qui sait exploiter les\nmétadonnées embarquées dans un binaire autonome (buildinfo Go\nvia `go-module-binary-cataloger`, classifieur générique pour\nquelques bibliothèques connues — OpenSSL, zlib, sqlite…).\nNe récupère PAS les dépendances de bibliothèques liées\nstatiquement sans métadonnée embarquée (C/C++ « fait maison »,\nRust sans cargo-auditable).'),
    )
    ..addOption(
      'oci-tool',
      defaultsTo: 'syft',
      help: tr('Backend d\'analyse OCI (utilisé avec --image).\n  syft    Anchore Syft (défaut) — tous types de paquets\n  trivy   Aqua Trivy — tous types de paquets\n  skopeo  Skopeo + extraction manuelle (dpkg/rpm/apk)\n  cdxgen  OWASP cdxgen — tous types de paquets'),
    )
    ..addFlag(
      'per-layer',
      negatable: false,
      help: tr('Avec --image : génère en plus un SBOM par couche de l\'image\n(delta de la couche : composants ajoutés/modifiés, supprimés\nlistés à part), dans chaque format demandé, à côté de -o :\n<base>.layer-NN-<digest12>.<ext>. Le SBOM global indique la\ncouche d\'origine de chaque composant.'),
    )
    ..addOption(
      'layer-mode',
      allowed: validLayerModes,
      help: tr('Méthode de calcul de --per-layer :\n  metadata  couche d\'origine indiquée par le backend (défaut ;\n            syft et trivy uniquement) — rapide, ajouts seulement\n  rootfs    couches appliquées une à une et rootfs réanalysé\n            après chacune — ajouts, modifications, suppressions\n            (défaut forcé pour skopeo et cdxgen)'),
    )
    ..addOption(
      'depth',
      defaultsTo: '0',
      help: tr('Profondeur de descente dans les objets imbriqués de --input :\n  0     l\'objet seul (défaut)\n  N     N niveaux (1 = jars/paquets/archives contenus dans un\n        rpm, deb, tar, zip, jar/war/ear, wheel ; 2 = ce que\n        contiennent ces derniers…)\n  all   sans limite (plafonné à {maxNestedDepth} niveaux)\nLes composants trouvés sont ajoutés au SBOM de l\'objet\n(propriétés location/depth, arêtes de dépendance parent → enfant)\net un SBOM par objet imbriqué est écrit à côté de -o\n(<base>.nested-NN-<objet>.<ext>, voir --no-nested-files).\nLes manifestes rencontrés (package-lock.json, go.sum, pom.xml…)\nsont analysés. Extraction bornée (taille, nombre de fichiers).', {'maxNestedDepth': maxNestedDepth}),
    )
    ..addFlag(
      'nested-files',
      defaultsTo: true,
      help: tr('Avec --depth : écrire un SBOM par objet imbriqué en plus du SBOM\nfusionné. --no-nested-files : fusionné seulement.'),
    )
    ..addOption(
      'output',
      abbr: 'o',
      defaultsTo: 'sbom.json',
      help: tr('Chemin du fichier de sortie.\nFormat unique : utilisé tel quel.\nPlusieurs formats (-f a,b) : utilisé comme base ; les extensions\npropres à chaque format sont ajoutées (.cdx.json, .spdx.json,\n.spdx3.jsonld, …).'),
    )
    ..addOption(
      'format',
      abbr: 'f',
      defaultsTo: 'cyclonedx',
      help: tr('Format(s) de sortie, séparés par des virgules.\n  cyclonedx  CycloneDX 1.6 ou 1.7 JSON (défaut : 1.6, voir --cyclonedx-version)\n  spdx       SPDX 2.3 JSON\n  spdx3      SPDX 3.0 JSON-LD\n  json       JSON lisible personnalisé\n  markdown   Tableau Markdown des licences\n  asciidoc   Tableau AsciiDoc des licences\n  html       Rapport HTML interactif (tableau filtrable)\n  csv        Fichier CSV (une ligne par paquet)\nExemple : -f cyclonedx,spdx,csv'),
    )
    ..addOption(
      'name',
      abbr: 'n',
      help: tr('Nom du document SBOM / du composant racine.'),
    )
    ..addOption(
      'supplier',
      help: tr('Fournisseur par défaut des composants dont la source ne porte\naucune information d\'éditeur (lockfiles npm/yarn/Go/pip/pub,\nrequirements.txt…). N\'écrase jamais un fournisseur déjà détecté\n(RPM %{VENDOR}, Maintainer Debian, groupId Maven…).\nChamp obligatoire de BSI TR-03183-2 / éléments minimaux NTIA.'),
    )
    ..addOption(
      'rpm-dir',
      abbr: 'd',
      help: tr('Dossier où chercher récursivement des fichiers .rpm.\nSert à résoudre les noms de paquet nus (sans chemin ni extension)\nvers des .rpm locaux au lieu d\'interroger la base installée.'),
    )
    ..addFlag(
      'verbose',
      abbr: 'v',
      defaultsTo: false,
      negatable: false,
      help:
          tr('Affiche le détail de la progression.'),
    )
    ..addOption(
      'log-format',
      allowed: ['text', 'json'],
      defaultsTo: 'text',
      help: tr('Format de la sortie standard.\n  text  texte lisible, barre de progression (défaut)\n  json  un événement JSON par ligne (NDJSON) :\n        {"event":"output","path":…,"kb":…},\n        {"event":"progress","current":…,"total":…,"label":…},\n        {"event":"log","message":…}. Les erreurs restent sur stderr.'),
    )
    ..addOption(
      'concurrency',
      abbr: 'c',
      defaultsTo: '4',
      help: tr('Nombre maximal de paquets traités en parallèle.\n1 = séquentiel. 0 = illimité.'),
    )
    ..addOption(
      'license-map',
      abbr: 'l',
      help: tr('Chemin d\'un fichier de substitution de licences.\nFormat : un « nom_de_paquet: expression-SPDX » par ligne ; la clé\npeut être un nom, un « groupId:artifactId » Maven ou un PURL sans\nversion (séparateur : « -> », « = » ou le dernier « : »).\nLes lignes commençant par # sont ignorées.\nRemplace la licence détectée pour les noms de paquet concernés.'),
    )
    ..addMultiOption(
      'deny-license',
      help: tr('Fait échouer la génération si un paquet a cette licence.\nPeut être répété. Supporte les expressions SPDX partielles.\nExemple : --deny-license GPL-3.0 --deny-license AGPL-3.0'),
    )
    ..addMultiOption(
      'sdk-version',
      help: tr('Version réelle d\'un SDK Dart/Flutter, pour les paquets\n`source: sdk` d\'un pubspec.lock/pubspec.yaml (que le lockfile\nnote toujours 0.0.0). Format <sdk>=<version>, répétable.\nExemple : --sdk-version flutter=3.47.2 --sdk-version dart=3.9.0'),
    )
    ..addOption(
      'pub-cache',
      help: tr('Répertoire du cache pub (contient hosted/<hôte>/<nom>-<version>/).\nSert à lire le fichier LICENSE de chaque paquet d\'un pubspec.lock\n(le lockfile ne contient aucune licence). Par défaut : \$PUB_CACHE,\nsinon ~/.pub-cache s\'il existe. Passer "" pour désactiver.'),
    )
    ..addOption(
      'flutter-root',
      help: tr('Racine du SDK Flutter, pour lire le LICENSE des paquets\n`source: sdk` (flutter, sky_engine…). Par défaut : \$FLUTTER_ROOT.'),
    )
    ..addOption(
      'cyclonedx-version',
      defaultsTo: '1.6',
      allowed: _validCycloneDxVersions,
      help: tr('Version de la spécification CycloneDX à générer.\n  1.6  (défaut, la plus répandue chez les consommateurs actuels)\n  1.7  Ajoute citations/patentAssertions/distributionConstraints quand --tlp ou --patent-map sont fournis.'),
    )
    ..addOption(
      'tlp',
      allowed: _validTlpClassifications,
      help: tr('Classification TLP (Traffic Light Protocol) du BOM.\nNécessite --cyclonedx-version 1.7.\nValeurs : {_validTlpClassifications}', {'_validTlpClassifications': _validTlpClassifications.join(", ")}),
    )
    ..addOption(
      'patent-map',
      help: tr('Chemin vers un fichier de déclarations de brevets.\nNécessite --cyclonedx-version 1.7.\nFormat : une ligne "nom_de_paquet: numéro|juridiction|statut|type"\nExemple : openssl: US1234567|US|granted|license'),
    )
    ..addOption(
      'min-quality-score',
      help: tr('Score sbomqs minimum (0-10). Échoue si le score est inférieur.\nRequiert que sbomqs soit installé.'),
    )
    ..addFlag(
      'sign',
      defaultsTo: false,
      negatable: false,
      help: tr('Signe le SBOM généré avec cosign (requiert cosign installé).\nLa clé est lue depuis les variables d\'environnement cosign standard.'),
    )
    ..addOption(
      'lang',
      allowed: ['fr', 'en'],
      help: tr('Langue des messages (défaut : SBOM_LANG, puis LC_ALL/LANG, sinon fr).'),
    )
    ..addFlag(
      'version',
      defaultsTo: false,
      negatable: false,
      help: tr('Affiche la version et quitte.'),
    )
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: tr('Affiche cette aide.'),
    );

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    _err(tr("Erreur d'argument : {message}", {'message': _argError(e.message)}));
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
    _err(tr('Au moins une source est requise : --input, --image ou --binary.'));
    _printUsage(parser);
    exit(1);
  }
  if (args.wasParsed('image') && args.wasParsed('binary')) {
    _err(tr('--image et --binary sont exclusifs (le second est un alias explicite du premier pour un fichier local).'));
    exit(1);
  }

  final inputPath = args['input'] as String?;
  final binaryPath = args['binary'] as String?;
  var ociTool = args['oci-tool'] as String;
  if (binaryPath != null) {
    if (!File(binaryPath).existsSync()) {
      _err(tr('--binary : fichier introuvable : {binaryPath}', {'binaryPath': binaryPath}));
      exit(1);
    }
    if (args.wasParsed('oci-tool') && ociTool != 'syft') {
      _err(tr('--binary ne fonctionne qu\'avec --oci-tool syft (seul backend capable d\'analyser un binaire autonome).'));
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
      _err(tr('--concurrency doit être ≥ 0.'));
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
    _err(tr('--format ne doit pas être vide.'));
    exit(1);
  }
  for (final f in formats) {
    if (!_validFormats.contains(f)) {
      _err(tr('Format inconnu "{f}". Valides : {_validFormats}', {'f': f, '_validFormats': _validFormats.join(', ')}));
      exit(1);
    }
  }

  // Validation --oci-tool
  if (!_validOciTools.contains(ociTool)) {
    _err(tr('Outil OCI inconnu "{ociTool}". Valides : {_validOciTools}', {'ociTool': ociTool, '_validOciTools': _validOciTools.join(', ')}));
    exit(1);
  }

  // Validation --per-layer / --layer-mode
  final perLayer = args['per-layer'] as bool;
  var layerMode = args['layer-mode'] as String?;
  if (layerMode != null && !perLayer) {
    _err(tr('--layer-mode nécessite --per-layer.'));
    exit(1);
  }
  if (perLayer) {
    if (binaryPath != null ||
        imageRef == null ||
        OciParser.detectRefType(imageRef) == OciRefType.binary) {
      _err(tr('--per-layer nécessite une image de conteneur (--image) : un binaire autonome n\'a pas de couches.'));
      exit(1);
    }
    if (layerMode == 'metadata' && !metadataLayerTools.contains(ociTool)) {
      _err(tr(
          "--layer-mode metadata nécessite --oci-tool {tools} ({ociTool} n'indique pas la couche d'origine des paquets) — utiliser --layer-mode rootfs.",
          {'tools': metadataLayerTools.join(tr(' ou ')), 'ociTool': ociTool}));
      exit(1);
    }
    if (layerMode == null) {
      layerMode = metadataLayerTools.contains(ociTool) ? 'metadata' : 'rootfs';
      if (layerMode == 'rootfs') {
        print(tr('--per-layer : mode rootfs (seul mode possible avec {ociTool}).', {'ociTool': ociTool}));
      }
    }
    // Le mode rootfs copie une image de registre en local via skopeo.
    if (layerMode == 'rootfs' &&
        ociTool != 'skopeo' &&
        OciParser.detectRefType(imageRef) == OciRefType.registry &&
        (await runTool('skopeo', ['--version'])).exitCode != 0) {
      _err(tr('--layer-mode rootfs sur une image de registre nécessite skopeo (copie locale des couches).'));
      exit(1);
    }
  }

  // Validation --depth
  final nestedDepth = parseNestedDepth(args['depth'] as String);
  if (nestedDepth == null) {
    _err(tr('--depth attend un entier ≥ 0 ou "all" (reçu "{depth}").', {'depth': args['depth']}));
    exit(1);
  }
  final nestedFiles = args['nested-files'] as bool;
  if (nestedDepth > 0 && inputPath == null) {
    _err(tr('--depth s\'applique aux objets de --input (rpm, deb, tar, zip, jar…) ; pour une image, voir --per-layer.'));
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
      _err(tr('--sdk-version attend <sdk>=<version> (reçu "{entry}").', {'entry': entry}));
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
    print(tr('Cache pub pour les licences : {pubCacheDir}', {'pubCacheDir': pubCacheDir}));
  }

  // Version du SDK Flutter : sans elle, le composant `flutter` d'un
  // pubspec.lock n'a pas de version et les scanners lui attribuent toutes les
  // CVE du SDK (faux positifs). Détectée au premier pubspec rencontré, sauf
  // si --sdk-version flutter=… est fourni.
  // `--sdk-version flutter=…` explicite : jamais écrasé. Sinon détection par
  // projet (FVM : `.fvmrc` / `.fvm/flutter_sdk`), puis Flutter installé.
  final flutterGiven = sdkVersions.containsKey('flutter');
  final flutterByDir = <String, String?>{};
  Map<String, String> sdkVersionsFor(String ref) {
    if (flutterGiven) return sdkVersions;
    final dir = File(ref).absolute.parent.path;
    final v = flutterByDir.putIfAbsent(dir, () {
      final d =
          detectFlutterVersion(flutterRoot: flutterRootDir, projectDir: dir);
      if (d != null) {
        stderr.writeln(tr('Version du SDK Flutter détectée pour {ref} : {d} ; pour une autre version : --sdk-version flutter=<version>.', {'ref': ref, 'd': d}));
      }
      return d;
    });
    if (v == null) return sdkVersions;
    // Métadonnées de l'outil (toolchain du SBOM) : première version vue.
    sdkVersions.putIfAbsent('flutter', () => v);
    return {...sdkVersions, 'flutter': v};
  }

  final minQualityScore = args['min-quality-score'] as String?;
  final signSbom = args['sign'] as bool;
  if (verbose && licenseOverrides.isNotEmpty) {
    print(tr('Substitutions de licence : {licenseOverrides} entrée(s) chargée(s).', {'licenseOverrides': licenseOverrides.length}));
  }

  // CycloneDX 1.7 : version cible + champs optionnels associés
  final cycloneDxVersion = args['cyclonedx-version'] as String;
  final tlp = args['tlp'] as String?;
  final patentMapPath = args['patent-map'] as String?;
  final patentMap = patentMapPath != null
      ? _parsePatentMap(patentMapPath)
      : <String, PatentAssertion>{};
  if (cycloneDxVersion != '1.7' && (tlp != null || patentMap.isNotEmpty)) {
    _err(tr('--tlp et --patent-map nécessitent --cyclonedx-version 1.7.'));
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
          tr('Entrée introuvable : {inputPath}', {'inputPath': inputPath}));
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
        print(tr('{found} fichier(s) de paquet trouvé(s) dans {inputPath}.', {'found': found.length, 'inputPath': inputPath}));
      }
      if (packageRefs.isEmpty && imageRef == null) {
        _err(tr('Aucun paquet reconnu dans le dossier {inputPath}.', {'inputPath': inputPath}));
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
        _err(tr('{inputPath} ne semble pas être un fichier texte lisible. Si c\'est une archive (.zip/.tar/.tar.gz/.tgz/.whl/.deb/.rpm/.jar), passez-la directement via --input, sinon --input doit être un fichier listant une référence de paquet par ligne, ou un dossier à scanner.', {'inputPath': inputPath}));
        exit(1);
      }
      packageRefs = lines
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty && !l.startsWith('#'))
          .toList();

      if (packageRefs.isEmpty && imageRef == null) {
        _err(tr('Aucun paquet trouvé dans {inputPath} (fichier vide ou lignes toutes commentées).', {'inputPath': inputPath}));
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
      _err(tr('Dossier RPM introuvable : {rpmDir}', {'rpmDir': rpmDir}));
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
      print(tr('{rpmExactIndex} fichier(s) RPM trouvé(s) dans {rpmDir}.', {'rpmExactIndex': rpmExactIndex.length, 'rpmDir': rpmDir}));
    }
  }

  // --- Expand manifest/lockfiles (preprocess before the main loop) ---
  final reqParser = RequirementsParser();
  final goParser = GoParser();
  final npmParser = NpmParser();
  final yarnParser = YarnParser();
  final cargoParser = CargoParser();
  final pnpmParser = PnpmParser();
  final composerParser = ComposerParser();
  final gemParser = GemParser();
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
    } else if (_isCargoLock(ref)) {
      preloadedPackages.addAll(cargoParser.parseCargoLock(ref));
    } else if (_isPnpmLock(ref)) {
      preloadedPackages.addAll(pnpmParser.parsePnpmLock(ref));
    } else if (_isComposerLock(ref)) {
      preloadedPackages.addAll(composerParser.parseComposerLock(ref));
    } else if (_isGemfileLock(ref)) {
      preloadedPackages.addAll(gemParser.parseGemfileLock(ref));
    } else if (_isPomXml(ref)) {
      preloadedPackages.addAll(mavenParser.parsePomXml(ref));
    } else if (_isPubspecLock(ref)) {
      preloadedPackages.addAll(pubspecParser.parsePubspecLock(ref,
          sdkVersions: sdkVersionsFor(ref),
          pubCache: pubCacheDir,
          flutterRoot: flutterRootDir));
    } else if (_isPubspecYaml(ref)) {
      preloadedPackages.addAll(pubspecParser.parsePubspecYaml(ref,
          sdkVersions: sdkVersionsFor(ref)));
    } else {
      filteredRefs.add(ref);
    }
  }
  if (preloadedPackages.any((p) =>
      p.packageType == 'pub' && p.name == 'flutter' && p.version.isEmpty)) {
    stderr.writeln(
        'Warning: ${tr('version du SDK Flutter inconnue : les scanners signaleront TOUTES les CVE du SDK, quelle que soit leur plage de versions. Fournir --sdk-version flutter=<version> (ou installer Flutter / définir FLUTTER_ROOT pour la détection automatique).')}');
  }
  final mainRefs = filteredRefs;

  // --- Analyse OCI image ---
  final ociPackages = <Package>[];
  OsInfo? ociOs;
  if (imageRef != null) {
    // Vérifier la disponibilité de l'outil OCI
    final ociCheck = await runTool(ociTool, ['--version']);
    if (ociCheck.exitCode != 0) {
      _err(tr('{ociTool} introuvable ou non fonctionnel — requis pour {image}.', {'ociTool': ociTool, 'image': binaryPath != null ? '--binary' : '--image'}));
      exit(1);
    }
    if (verbose) {
      print(
          '$ociTool : ${(ociCheck.stdout as String).split('\n').first.trim()}');
    }

    final refType = OciParser.detectRefType(imageRef);
    if (refType == OciRefType.binary) {
      print(tr('Analyse du binaire via {ociTool} : {imageRef}…', {'ociTool': ociTool, 'imageRef': imageRef}));
    } else {
      final refTypeLabel = switch (refType) {
        OciRefType.registry => tr('registre'),
        OciRefType.tar => tr('archive tar'),
        OciRefType.ociLayout => 'OCI layout',
        OciRefType.binary =>
          tr('binaire'), // inatteignable (branche ci-dessus)
      };
      print(tr('Analyse de l\'image OCI ({refTypeLabel}) via {ociTool} : {imageRef}…', {'refTypeLabel': refTypeLabel, 'ociTool': ociTool, 'imageRef': imageRef}));
    }

    try {
      final ociResult =
          await OciParser().parseImage(imageRef, ociTool, verbose: verbose);
      ociPackages.addAll(ociResult.packages);
      ociOs = ociResult.os;
      print(tr('{ociPackages} paquet(s) trouvé(s) dans l\'image.', {'ociPackages': ociPackages.length}));
      if (verbose && ociOs != null) {
        print(tr('OS de base détecté : {id} {version}', {'id': ociOs.id, 'version': ociOs.version}));
      }
    } catch (e) {
      _err(tr('Échec de l\'analyse OCI : {e}', {'e': e}));
      exit(1);
    }
  }

  // --- Analyse par couche (--per-layer) ---
  LayerAnalysis? layerAnalysis;
  if (perLayer) {
    print(tr('Analyse par couche (mode {layerMode}) via {ociTool}…', {'layerMode': layerMode, 'ociTool': ociTool}));
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
          stderr.writeln(tr('⚠  {unattributed} paquet(s) sans couche d\'origine connue — absents des SBOM de couche.', {'unattributed': unattributed}));
        }
      } else {
        layerAnalysis = await parser.rootfsLayerAnalysis(imageRef!, ociTool,
            verbose: verbose, log: print);
      }
      print(tr('{layers} couche(s) analysée(s).', {'layers': layerAnalysis.layers.length}));
    } catch (e) {
      _err(tr('Échec de l\'analyse par couche : {e}', {'e': e}));
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
    final rpmCheck = await runTool('rpm', ['--version']);
    if (rpmCheck.exitCode != 0) {
      _err(tr('binaire rpm introuvable ou non fonctionnel.'));
      exit(1);
    }
    if (verbose) print('rpm: ${(rpmCheck.stdout as String).trim()}');
  }

  if (hasWhl || hasTar || hasZip) {
    final py3Check = await runTool('python3', ['--version']);
    if (py3Check.exitCode != 0) {
      _err(tr('python3 introuvable — requis pour lire les archives .whl, tar et zip.'));
      exit(1);
    }
    if (verbose) print('python3: ${(py3Check.stdout as String).trim()}');
  }

  if (hasDeb) {
    final debCheck = await runTool('dpkg-deb', ['--version']);
    if (debCheck.exitCode != 0) {
      _err(tr('dpkg-deb introuvable — requis pour lire les fichiers .deb.'));
      exit(1);
    }
    if (verbose)
      print(
          'dpkg-deb: ${(debCheck.stdout as String).split('\n').first.trim()}');
  }

  if (hasJar) {
    final unzipCheck = await runTool('unzip', ['-v']);
    if (unzipCheck.exitCode != 0) {
      _err(tr('unzip introuvable — requis pour lire les fichiers .jar.'));
      exit(1);
    }
    if (verbose) {
      print('unzip: ${(unzipCheck.stdout as String).split('\n').first.trim()}');
    }
  }

  // --- Parse packages ---
  final conLabel =
      concurrencyN == 0 ? tr('illimité') : '$concurrencyN';
  if (mainRefs.isNotEmpty) {
    print(tr('Interrogation de {count} paquet(s) — concurrence : {con}{manifests}…', {
          'count': mainRefs.length,
          'con': conLabel,
          'manifests': preloadedPackages.isNotEmpty
              ? tr(' (+ {n} depuis les manifestes)',
                  {'n': preloadedPackages.length})
              : '',
        }));
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
                    tr('plusieurs fichiers RPM correspondent à "{ref}" ; utilisation de {last}', {'ref': ref, 'last': paths.first.split('/').last}));
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

  if (mainTotal > 0 && !_jsonLog) stdout.writeln();

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
      stderr.writeln(tr('--depth : aucun objet de --input dans lequel descendre (rpm, deb, tar, zip, jar, wheel).'));
    } else {
      print(tr('Descente dans {roots} objet(s) (profondeur {nestedDepth})…', {'roots': roots.length, 'nestedDepth': nestedDepth == maxNestedDepth ? 'max' : nestedDepth}));
    }
    for (final (path, primaryRef) in roots) {
      final res = await explorer.explore(path, rootPrimaryRef: primaryRef);
      nestedObjects.addAll(res.objects);
      for (final w in res.warnings) {
        stderr.writeln('⚠  $w');
      }
    }
    nestedCount = nestedObjects.fold<int>(0, (n, o) => n + o.packages.length);
    print(tr('{nestedCount} composant(s) trouvé(s) dans {nestedObjects} objet(s) imbriqué(s).', {'nestedCount': nestedCount, 'nestedObjects': nestedObjects.length}));
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
      print(tr('Substitutions de licence appliquées à {n} paquet(s).', {'n': n}));
    }
  }

  // --- Apply supplier fallback ---
  final supplierFallback = (args['supplier'] as String?)?.trim() ?? '';
  if (supplierFallback.isNotEmpty) {
    final before = uniquePackages.where((p) => p.vendor.trim().isEmpty).length;
    uniquePackages = _applySupplierFallback(uniquePackages, supplierFallback);
    if (verbose) {
      print(tr('Fournisseur par défaut "{supplierFallback}" appliqué à {before} paquet(s) sans fournisseur détecté.', {'supplierFallback': supplierFallback, 'before': before}));
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
      failed > 0 ? tr('  ({failed} échec(s))', {'failed': failed}) : '';
  final dupeNote = dupes > 0
      ? tr('  ({dupes} doublon(s) supprimé(s))', {'dupes': dupes})
      : '';
  // Dénominateur = tous les paquets visés : références interrogées, paquets
  // issus des manifestes, paquets d'image et composants imbriqués.
  final targeted = mainRefs.length +
      preloadedPackages.length +
      ociPackages.length +
      nestedCount;
  print(tr('Analysés : {uniquePackages}/{targeted} paquet(s).{failedNote}{dupeNote}', {'uniquePackages': uniquePackages.length, 'targeted': targeted, 'failedNote': failedNote, 'dupeNote': dupeNote}));

  // --- Error report ---
  if (failedRefs.isNotEmpty) {
    stderr.writeln('');
    stderr.writeln(tr('⚠  {failedRefs} paquet(s) ignoré(s) :', {'failedRefs': failedRefs.length}));
    for (final r in failedRefs) {
      final name = r.contains('/') ? r.split('/').last : r;
      stderr.writeln('   • $name');
    }
    stderr.writeln('');
  }

  if (uniquePackages.isEmpty) {
    _err(tr('Aucun paquet n\'a pu être analysé. Abandon.'));
    exit(1);
  }

  // --- Build dependency graph (skipped when all formats are markdown) ---
  final dependencies = <PackageDependency>[];
  if (formats.any((f) => f != 'markdown' && f != 'asciidoc' && f != 'html')) {
    print(tr('Résolution des dépendances…'));
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
    print(tr('{relCount} relation(s) de dépendance trouvée(s) dans la liste.', {'relCount': relCount}));

    if (verbose) {
      for (final dep in dependencies.where((d) => d.dependsOn.isNotEmpty)) {
        final srcName = uniquePackages
            .firstWhere((p) => p.bomRef == dep.sourceRef,
                orElse: () => uniquePackages.first)
            .name;
        print(tr('  {srcName} → {dependsOn} dépendance(s)', {'srcName': srcName, 'dependsOn': dep.dependsOn.length}));
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
      print(tr('Génération de {label} ({fmt})…', {'label': label, 'fmt': fmt}));
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
        _err(tr('Échec d\'écriture de {label} ({fmt}) : {e}', {'label': label, 'fmt': fmt, 'e': e}));
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
        label: tr('SBOM couche {index}/{total}', {'index': layer.index, 'total': total}),
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

  await writeAll(
    uniquePackages,
    dependencies,
    (fmt) => _outputPathFor(outputPath, formats, fmt),
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
        label: tr('SBOM objet imbriqué {i}/{nestedJobs}', {'i': i + 1, 'nestedJobs': nestedJobs.length}),
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
      stderr.writeln(tr('\nPolitique licence : {violations} violation(s) :', {'violations': violations.length}));
      for (final v in violations) {
        stderr.writeln('  [DENY] ${v.packageName} ${v.version} — ${v.license}');
      }
      policyFailures += violations.length;
    } else if (verbose) {
      print(tr('Politiques licences : OK'));
    }
  }

  if (minQualityScore != null) {
    final threshold = double.tryParse(minQualityScore);
    if (threshold == null) {
      stderr.writeln(tr('--min-quality-score : valeur invalide "{minQualityScore}"', {'minQualityScore': minQualityScore}));
      exit(1);
    }
    final primaryOut = _outputPathFor(outputPath, formats, formats.first);
    final score = await checker.runSbomqs(primaryOut, verbose: verbose);
    if (score != null) {
      if (score < threshold) {
        stderr.writeln(tr('\nPolitique qualité : score={score} < seuil={threshold} → ÉCHEC', {'score': score, 'threshold': threshold}));
        policyFailures++;
      } else if (verbose) {
        print(tr('Politique qualité : score={score} >= seuil={threshold} → OK', {'score': score, 'threshold': threshold}));
      }
    }
  }

// ── Signature cosign ─────────────────────────────────────────────────────
  if (signSbom) {
    final primaryOut = _outputPathFor(outputPath, formats, formats.first);
    await _signWithCosign(primaryOut, verbose: verbose);
    for (final p in [...layerPrimaryPaths, ...nestedPrimaryPaths]) {
      await _signWithCosign(p, verbose: verbose);
    }
  }

  if (policyFailures > 0) {
    stderr.writeln(tr('\n{policyFailures} politique(s) violée(s) — code retour 2', {'policyFailures': policyFailures}));
    exit(2);
  }
}

// ── Sous-commande diff ────────────────────────────────────────────────────────

Future<void> _runDiff(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('output',
        abbr: 'o',
        help: tr('Fichier de sortie (JSON). Défaut : affichage console.'))
    ..addFlag('json',
        defaultsTo: false,
        negatable: false,
        help: tr('Sortie au format JSON structuré.'))
    ..addFlag('no-color',
        defaultsTo: false,
        negatable: false,
        help: tr('Désactive la coloration ANSI.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('diff: ${_argError(e.message)}');
    _printDiffUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printDiffUsage(parser);
    exit(0);
  }

  final rest = args.rest;
  if (rest.length != 2) {
    stderr.writeln(tr('diff: deux fichiers SBOM requis.'));
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
      print(tr('Diff écrit → {outPath}', {'outPath': outPath}));
    } else {
      print(jsonStr);
    }
  } else {
    differ.printDiff(result, color: !(args['no-color'] as bool));
  }

  exit(result.isEmpty ? 0 : 1);
}

void _printDiffUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator diff – Compare deux fichiers SBOM et affiche les changements.\n\nUsage:\n  sbom_generator diff <avant.cdx.json> <après.cdx.json> [options]\n\n{usage}\n\nCodes de retour:\n  0  Aucun changement\n  1  Des changements ont été détectés\n', {'usage': parser.usage}));
}

// ── Sous-commande merge ───────────────────────────────────────────────────────

Future<void> _runMerge(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('output',
        abbr: 'o',
        mandatory: true,
        help: tr('Fichier SBOM fusionné de sortie (même format que le premier fichier d\'entrée : .cdx.json ou .spdx.json).'))
    ..addOption('name',
        abbr: 'n',
        help: tr('Nom du document SBOM fusionné.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('merge: ${_argError(e.message)}');
    _printMergeUsage(parser);
    exit(1);
  }
  if (!(args['help'] as bool)) {
    _requireMandatory(parser, args, 'merge', () => _printMergeUsage(parser));
  }
  if (args['help'] as bool) {
    _printMergeUsage(parser);
    exit(0);
  }

  final files = args.rest;
  if (files.length < 2) {
    stderr.writeln(tr('merge: au moins deux fichiers SBOM requis.'));
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
  print(tr('Fusion de {files} SBOMs → {total} composant(s) → {outPath}', {'files': files.length, 'total': total, 'outPath': outPath}));
}

void _printMergeUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator merge – Fusionne plusieurs fichiers SBOM en un seul.\n\nUsage:\n  sbom_generator merge <a.cdx.json> <b.cdx.json> [...] -o merged.cdx.json\n\n{usage}\n', {'usage': parser.usage}));
}

/// Traduit les messages d'erreur du paquet `args` (toujours en anglais) dans
/// la langue courante ; un message inconnu est renvoyé tel quel.
String _argError(String message) {
  if (currentLang == Lang.en) return message;
  final rules = <(RegExp, String Function(Match))>[
    (
      RegExp(r'^Could not find an option named "(.+)"\.$'),
      (m) => 'Option inconnue "${m[1]}".'
    ),
    (
      RegExp(r'^Could not find an option or flag "(.+)"\.$'),
      (m) => 'Option ou drapeau inconnu "${m[1]}".'
    ),
    (
      RegExp(r'^Could not find an option with short name "(.+)"\.$'),
      (m) => 'Option inconnue "${m[1]}".'
    ),
    (
      RegExp(r'^Missing argument for "(.+)"\.$'),
      (m) => 'Valeur manquante pour "${m[1]}".'
    ),
    (
      RegExp(r'^"(.*)" is not an allowed value for option "(.+)"\.$'),
      (m) =>
          '"${m[1]}" n\'est pas une valeur autorisée pour l\'option "${m[2]}".'
    ),
    (
      RegExp(r'^Flag option "(.+)" should not be given a value\.$'),
      (m) => 'L\'option "${m[1]}" n\'accepte pas de valeur.'
    ),
    (
      RegExp(r'^Option (.+) is mandatory\.$'),
      (m) => 'L\'option --${m[1]} est obligatoire.'
    ),
    (
      RegExp(r'^Cannot specify arguments before a command\.$'),
      (m) => 'Aucun argument n\'est permis avant une commande.'
    ),
  ];
  for (final (re, f) in rules) {
    final m = re.firstMatch(message);
    if (m != null) return f(m);
  }
  return message;
}

/// Vérifie les options `mandatory` d'une sous-commande. Le paquet `args` ne
/// les contrôle qu'à l'accès (`ArgumentError` non rattrapée) : on les contrôle
/// ici, juste après l'analyse, pour afficher une erreur d'usage et sortir en
/// code 1.
void _requireMandatory(
    ArgParser parser, ArgResults args, String command, void Function() usage) {
  for (final o in parser.options.values) {
    if (o.mandatory && !args.wasParsed(o.name)) {
      stderr
          .writeln('$command: ${_argError('Option ${o.name} is mandatory.')}');
      usage();
      exit(1);
    }
  }
}

/// Date `AAAA-MM-JJ` stricte (jour calendaire existant) ou `null`. Évite que
/// `DateTime.tryParse` n'accepte `2024-13-45` en le décalant au 14/02/2025.
DateTime? _parseCliDate(String raw) {
  final m = RegExp(r'^(\d{4})-(\d{2})-(\d{2})$').firstMatch(raw.trim());
  if (m == null) return null;
  final y = int.parse(m[1]!), mo = int.parse(m[2]!), d = int.parse(m[3]!);
  final dt = DateTime(y, mo, d);
  return (dt.year == y && dt.month == mo && dt.day == d) ? dt : null;
}

// ── Signature cosign ──────────────────────────────────────────────────────────

Future<void> _signWithCosign(String sbomPath, {bool verbose = false}) async {
  // `Process.run` lève une ProcessException quand le binaire est absent du
  // PATH : même traitement qu'un code de retour non nul.
  final check = await Process.run('cosign', ['version'])
      .catchError((Object _) => ProcessResult(0, 127, '', ''));
  if (check.exitCode != 0) {
    stderr.writeln(tr('sign: cosign introuvable — signature ignorée.'));
    return;
  }
  if (verbose)
    print(tr('cosign : signature de {sbomPath}…', {'sbomPath': sbomPath}));
  final result = await Process.run('cosign', [
    'sign-blob',
    '--yes',
    '--bundle',
    '$sbomPath.bundle',
    sbomPath,
  ]);
  if (result.exitCode != 0) {
    stderr.writeln(tr('cosign: échec (code {exitCode}) : {stderr}', {'exitCode': result.exitCode, 'stderr': result.stderr}));
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
bool _isCargoLock(String ref) => ref.endsWith('Cargo.lock');
bool _isPnpmLock(String ref) => ref.endsWith('pnpm-lock.yaml');
bool _isComposerLock(String ref) => ref.endsWith('composer.lock');
bool _isGemfileLock(String ref) => ref.endsWith('Gemfile.lock');
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
      base == 'Cargo.lock' ||
      base == 'pnpm-lock.yaml' ||
      base == 'composer.lock' ||
      base == 'Gemfile.lock' ||
      base == 'pubspec.lock' ||
      base == 'pubspec.yaml';
}

/// Le préfixe `Error:` est lu par la GUI (coloration, erreur fatale) : jamais
/// traduit — seul le message l'est.
void _err(String msg) => stderr.writeln('Error: $msg');

void _printProgress(int current, int total, String label) {
  if (_jsonLog) {
    print(jsonEncode({
      'event': 'progress',
      'current': current,
      'total': total,
      'label': label,
    }));
    return;
  }
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
    '.html',
    '.csv',
  ];
  for (final ext in exts) {
    if (output.endsWith(ext)) {
      return output.substring(0, output.length - ext.length);
    }
  }
  return output;
}

/// Chemin du fichier écrit pour [fmt] : avec plusieurs formats, le chemin de
/// base (extension SBOM connue retirée) + l'extension du format ; avec un
/// seul format, [output] tel quel s'il porte déjà une extension SBOM connue,
/// sinon complété par l'extension du format (`-o sbom` → `sbom.cdx.json`).
String _outputPathFor(String output, List<String> formats, String fmt) {
  final base = _basePath(output);
  if (formats.length == 1 && base != output) return output;
  return '$base${_formatExtension(fmt)}';
}

// ── License override helpers ──────────────────────────────────────────────────

/// Analyse un fichier de substitution de licences (une ligne « nom: expression-SPDX »).
Map<String, String> _parseLicenseMap(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    _err(tr('Fichier de correspondance de licences introuvable : {path}', {'path': path}));
    exit(1);
  }
  final result = <String, String>{};
  for (final line in file.readAsLinesSync()) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
    // Séparateur : `->`, puis `=`, sinon le DERNIER `:` (une licence ne
    // contient pas de `:`, alors qu'un nom Maven « groupId:artifactId » ou un
    // PURL oui).
    var idx = trimmed.indexOf('->');
    var sepLen = 2;
    if (idx < 1) {
      idx = trimmed.indexOf('=');
      sepLen = 1;
    }
    if (idx < 1) {
      idx = trimmed.lastIndexOf(':');
      sepLen = 1;
    }
    if (idx < 1) continue;
    final name = trimmed.substring(0, idx).trim();
    final license = trimmed.substring(idx + sepLen).trim();
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
    _err(tr('Fichier de brevets introuvable : {path}', {'path': path}));
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
      _err(tr('--patent-map : ligne invalide (attendu "name: number|jurisdiction|status|type") : "{trimmed}"', {'trimmed': trimmed}));
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
        help: tr('Chemin vers le fichier SBOM à analyser (.cdx.json, .spdx.json…).\nExclusif de --image.'))
    ..addOption('image',
        abbr: 'I',
        help: tr('Image de conteneur à analyser (registre, archive tar, OCI\nlayout) : son SBOM CycloneDX est d\'abord généré (via\n--oci-tool) dans un répertoire temporaire, puis scanné.\nExclusif de --sbom.'))
    ..addOption('package',
        abbr: 'p',
        help: tr('Paquet ou archive local à analyser directement (rpm, deb,\ntar/tgz, zip, jar/war/ear, wheel) : son SBOM CycloneDX est\nd\'abord généré (voir --depth) dans un répertoire temporaire,\npuis scanné. Exclusif de --sbom et --image.'))
    ..addOption('depth',
        defaultsTo: '0',
        help: tr('Avec --package : profondeur de descente dans les objets\nimbriqués (0 = l\'objet seul, N niveaux, all = sans limite),\ncomme --depth de la génération. Chaque CVE est rattachée à\nl\'objet qui contient le paquet vulnérable (colonne OBJET).'))
    ..addOption('oci-tool',
        defaultsTo: 'syft',
        allowed: _validOciTools,
        help: tr('Backend de génération du SBOM pour --image.'))
    ..addFlag('per-layer',
        negatable: false,
        help: tr('Vulnérabilités par couche d\'image. Avec --sbom, le SBOM doit\nêtre le SBOM global d\'un jeu produit par --per-layer (SBOM de\ncouche à côté) ; avec --image, le jeu est généré.'))
    ..addOption('layer-scan',
        allowed: validLayerScanModes,
        defaultsTo: 'attribute',
        help: tr('Méthode de --per-layer :\n  attribute  un scan du SBOM global, chaque CVE rattachée à la\n             couche d\'origine de son paquet (défaut)\n  each       SBOM de chaque couche scanné séparément (CVE\n             introduites puis corrigées plus haut incluses)'))
    ..addOption('layer-mode',
        allowed: validLayerModes,
        help: tr('Avec --image --per-layer : calcul des couches (voir\n--layer-mode de la génération ; défaut metadata pour\nsyft/trivy, rootfs sinon).'))
    ..addOption('scanner',
        abbr: 'S',
        defaultsTo: 'grype',
        help: tr('Scanner(s) à utiliser.\n  grype   Anchore Grype\n  osv     Google OSV-Scanner\n  trivy   Aqua Security Trivy\n  all     Les trois scanners'))
    ..addOption('cve-after',
        help: tr('N\'afficher que les CVE publiées/modifiées après cette date (YYYY-MM-DD)'))
    ..addOption('cve-before',
        help: tr('N\'afficher que les CVE publiées/modifiées avant cette date (YYYY-MM-DD)'))
    ..addOption('cve-date-field',
        defaultsTo: 'published',
        help: tr('Champ de date à utiliser pour le filtre.\n  published   Date de publication (défaut)\n  modified    Date de dernière modification\n  latest      La plus récente des deux'))
    ..addFlag('include-undated',
        defaultsTo: false,
        negatable: false,
        help: tr('Inclure les CVE sans date dans les résultats filtrés'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'text',
        help: tr('Format de sortie.\n  text      Texte coloré sur stdout (défaut)\n  json      Résultats en JSON (stdout si -o omis) ; sert de\n            référence pour --baseline\n  sarif     SARIF 2.1.0 (intégration GitHub Code Scanning)\n  markdown  Rapport de synthèse inter-scanners (Markdown)\n  asciidoc  Rapport de synthèse inter-scanners (AsciiDoc)\n  pdf       Idem asciidoc + conversion via asciidoctor-pdf'))
    ..addOption('output',
        abbr: 'o',
        help: tr('Fichier de sortie. Requis pour --format markdown/asciidoc/pdf ;\npour --format sarif/json, écrit sur stdout si omis.'))
    ..addOption('color',
        allowed: ['auto', 'always', 'never'],
        defaultsTo: 'auto',
        help: tr('Coloration ANSI des alertes Critical/High (formats rapport).\n  auto    si stdout est un terminal et NO_COLOR non défini (défaut)\n  always  toujours (utile derrière un pipe : build-dist.sh)\n  never   jamais (préfixes [CRITICAL]/[HIGH])'))
    ..addFlag('enrich',
        defaultsTo: true,
        help: tr('Enrichir chaque CVE avec les signaux d\'exploitabilité :\n  CISA KEV (exploitée dans la nature), EPSS (probabilité),\n  PoC public, sous-score d\'exploitabilité CVSS.\n  --no-enrich : hors-ligne, uniquement ce que les scanners\n  fournissent déjà + le cache local. Forcé par SBOMGEN_OFFLINE=1.'))
    ..addFlag('poc',
        defaultsTo: true,
        help: tr('Interroger la source PoC tierce (poc-in-github). --no-poc\ngarde KEV/EPSS et la maturité « E: » du vecteur CVSS.'))
    ..addOption('enrich-timeout',
        defaultsTo: '8',
        help: tr('Délai maximal (secondes) par requête d\'enrichissement.'))
    ..addFlag('only-kev',
        negatable: false,
        help: tr('Ne garder que les CVE présentes au catalogue CISA KEV.'))
    ..addOption('epss-min',
        help: tr('Ne garder que les CVE dont le score EPSS est ≥ cette valeur (0..1, ex. 0.1).'))
    ..addOption('sort',
        allowed: ['severity', 'risk'],
        defaultsTo: 'severity',
        help: tr('Ordre d\'affichage console.\n  severity  pire sévérité d\'abord (défaut)\n  risk      KEV, puis EPSS décroissant, puis sévérité'))
    ..addOption('vex',
        help: tr('Document VEX (OpenVEX, CSAF ou CycloneDX VEX) : les CVE déclarées\n"not_affected" ou "fixed" pour le paquet concerné sont\nécartées des résultats (et comptées).'))
    ..addOption('vex-out',
        help: tr('Écrit un document VEX : les CVE restantes en "affected" (avec\nla version corrigée), plus les déclarations "not_affected"\nreprises de --vex.'))
    ..addOption('vex-format',
        allowed: ['openvex', 'cyclonedx', 'csaf'],
        defaultsTo: 'openvex',
        help: tr('Format de --vex-out.'))
    ..addOption('vex-author',
        defaultsTo: 'sbom-generator',
        help: tr('Auteur inscrit dans --vex-out.'))
    ..addOption('ignore',
        help: tr('Fichier de CVE ignorées, une règle par ligne :\n  CVE-2024-1234; package=openssl; expires=2026-12-31; reason=…\n(seul l\'identifiant est obligatoire ; une règle expirée\nn\'est plus appliquée et est signalée).'))
    ..addOption('baseline',
        help: tr('Rapport de référence produit par `scan --format json` : les\nCVE déjà présentes (même identifiant, même paquet) sont\nécartées ; seules les NOUVELLES restent.'))
    ..addOption('fail-on',
        allowed: severityLevels,
        help: tr('Code retour 1 seulement si une CVE restante a au moins cette\nsévérité (critical, high, medium, low). Par défaut : toute\nCVE restante fait échouer.'))
    ..addOption('report-severity',
        allowed: ScanReportGenerator.thresholds,
        defaultsTo: 'all',
        help: tr('Rapports (markdown/asciidoc/pdf) : ne garder que les CVE dont la\npire sévérité atteint ce seuil (critical, high, medium), plus\ncelles du catalogue CISA KEV. Défaut : all.'))
    ..addOption('compare-with',
        help: tr('Rapports : section « Tendance » par rapport à un `scan --format\njson` antérieur (ou une session de la GUI).'))
    ..addFlag('cache',
        negatable: false,
        help: tr('Réutilise le résultat d\'un scanner déjà obtenu pour le même\ncontenu de SBOM (même composants), la même version du scanner,\ndans la limite de --cache-ttl. Évite de relancer le scanner.'))
    ..addOption('cache-ttl',
        defaultsTo: '6',
        help: tr('Durée de validité du cache, en heures (la base de\nvulnérabilités évolue).'))
    ..addOption('cache-dir',
        help: tr('Répertoire du cache (défaut : ~/.cache/sbom-generator/scan).'))
    ..addFlag('help',
        abbr: 'h',
        negatable: false,
        help: tr('Afficher l\'aide de la sous-commande scan'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('scan: ${_argError(e.message)}');
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
    stderr.writeln(tr('scan: indiquer --sbom <fichier>, --image <image> ou --package <fichier> (exactement l\'un des trois).'));
    _printScanUsage(parser);
    exit(1);
  }
  final scanDepthRaw = args['depth'] as String;
  final scanDepth = parseNestedDepth(scanDepthRaw);
  if (scanDepth == null) {
    stderr.writeln(tr('scan: --depth attend un entier ≥ 0 ou "all" (reçu "{scanDepthRaw}").', {'scanDepthRaw': scanDepthRaw}));
    exit(1);
  }
  if (args.wasParsed('depth') && packageRef == null) {
    stderr.writeln(tr('scan: --depth nécessite --package.'));
    exit(1);
  }
  if (packageRef != null) {
    if (args['per-layer'] as bool) {
      stderr.writeln(tr('scan: --per-layer ne s\'applique qu\'aux images (--image / --sbom d\'un jeu par couche).'));
      exit(1);
    }
    if (!File(packageRef).existsSync()) {
      stderr.writeln(tr('scan: fichier introuvable : {packageRef}', {'packageRef': packageRef}));
      exit(1);
    }
  }
  final perLayer = args['per-layer'] as bool;
  final layerScan = args['layer-scan'] as String;
  final layerMode = args['layer-mode'] as String?;
  if (layerMode != null && (imageRef == null || !perLayer)) {
    stderr.writeln(tr('scan: --layer-mode nécessite --image et --per-layer.'));
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
      stderr.writeln(tr('scan: --epss-min doit être un nombre entre 0 et 1 (reçu "{rawEpssMin}")', {'rawEpssMin': rawEpssMin}));
      exit(1);
    }
  }
  var enrichTimeout = int.tryParse(args['enrich-timeout'] as String) ?? 8;
  if (enrichTimeout < 1) enrichTimeout = 8;

  if (!_validScanners.contains(scanner)) {
    stderr.writeln(tr('scan: scanner invalide "{scanner}". Valides : {_validScanners}', {'scanner': scanner, '_validScanners': _validScanners.join(', ')}));
    exit(1);
  }
  if (!_validDateFields.contains(dateField)) {
    stderr.writeln(tr('scan: cve-date-field invalide "{dateField}". Valides : {_validDateFields}', {'dateField': dateField, '_validDateFields': _validDateFields.join(', ')}));
    exit(1);
  }
  if (!_validScanFormats.contains(format)) {
    stderr.writeln(tr('scan: format invalide "{format}". Valides : {_validScanFormats}', {'format': format, '_validScanFormats': _validScanFormats.join(', ')}));
    exit(1);
  }
  if (imageRef == null &&
      packageRef == null &&
      !await File(sbomFile).exists()) {
    stderr.writeln(tr('scan: fichier SBOM introuvable : {sbomFile}', {'sbomFile': sbomFile}));
    exit(1);
  }

  DateTime? after, before;
  final rawAfter = args['cve-after'] as String?;
  final rawBefore = args['cve-before'] as String?;
  if (rawAfter != null) {
    after = _parseCliDate(rawAfter);
    if (after == null) {
      stderr.writeln(tr('scan: format de date invalide pour --cve-after : "{rawAfter}" (attendu YYYY-MM-DD)', {'rawAfter': rawAfter}));
      exit(1);
    }
  }
  if (rawBefore != null) {
    before = _parseCliDate(rawBefore);
    if (before == null) {
      stderr.writeln(tr('scan: format de date invalide pour --cve-before : "{rawBefore}" (attendu YYYY-MM-DD)', {'rawBefore': rawBefore}));
      exit(1);
    }
    // La date "avant" est inclusive en fin de journée
    before = before.add(const Duration(hours: 23, minutes: 59, seconds: 59));
  }

  final isReport = _reportScanFormats.contains(format);
  if (isReport && outputPath == null) {
    stderr.writeln(tr('scan: --output <fichier> est requis pour --format {format}.', {'format': format}));
    exit(1);
  }

  final scanners = scanner == 'all' ? ['grype', 'osv', 'trivy'] : [scanner];

  final quiet = format == 'sarif' || format == 'json' || isReport;

  // ── Politique : VEX, CVE ignorées, référence, seuil, cache ──────────────
  void policyError(String message) {
    stderr.writeln('scan: $message');
    exit(1);
  }

  final vexPath = args['vex'] as String?;
  final vexDoc = vexPath != null ? _loadVexOrExit('scan', vexPath) : null;
  final ignorePath = args['ignore'] as String?;
  final ignoreList =
      ignorePath != null ? _loadIgnoreOrExit('scan', ignorePath) : null;
  Baseline? baseline;
  final baselinePath = args['baseline'] as String?;
  if (baselinePath != null) {
    try {
      baseline = Baseline.load(baselinePath);
    } on FileSystemException {
      policyError(tr('fichier --baseline introuvable : {path}',
          {'path': baselinePath}));
    } on FormatException catch (e) {
      policyError(tr('--baseline : {message}', {'message': e.message}));
    }
  }
  final failOn = args['fail-on'] as String?;
  final cacheTtlHours = int.tryParse(args['cache-ttl'] as String);
  if (cacheTtlHours == null || cacheTtlHours < 0) {
    policyError(tr("--cache-ttl attend un nombre d'heures entier ≥ 0."));
  }
  final scanCache = (args['cache'] as bool)
      ? ScanCache(
          args['cache-dir'] != null
              ? Directory(args['cache-dir'] as String)
              : ScanCache.defaultDir(),
          Duration(hours: cacheTtlHours!))
      : null;
  final scannerVersions = <String, String>{};
  Future<List<Map<String, dynamic>>?> runScannerCached(
      String s, String sbomPath) async {
    if (scanCache == null) return _runScanner(s, sbomPath, quiet: quiet);
    final ver = scannerVersions[s] ??= await _scannerVersion(s) ?? '';
    final digest = ScanCache.sbomDigest(sbomPath);
    final hit =
        ver.isEmpty ? null : scanCache.read(digest, s, ver, DateTime.now());
    if (hit != null) {
      stderr.writeln(tr('scan: résultat {s} lu dans le cache (--cache).', {'s': _scannerTitle(s)}));
      return hit;
    }
    final fresh = await _runScanner(s, sbomPath, quiet: quiet);
    if (fresh != null && ver.isNotEmpty) {
      scanCache.write(digest, s, ver, fresh, DateTime.now());
    }
    return fresh;
  }

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
    stderr.writeln(tr('Génération du SBOM de {packageRef}{depth}…', {
          'packageRef': packageRef,
          'depth': scanDepth > 0
              ? tr(' (profondeur {d})', {
                  'd': scanDepth == maxNestedDepth ? tr('max') : scanDepth
                })
              : '',
        }));
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
      stderr.writeln(tr('scan: échec de la génération du SBOM de {packageRef} (code {code}).', {'packageRef': packageRef, 'code': code}));
      await quit(1);
    }
  }

  if (imageRef != null) {
    tmpDir = await Directory.systemTemp.createTemp('sbom_scan_');
    sbomFile = '${tmpDir.path}/image.cdx.json';
    stderr.writeln(tr('Génération du SBOM de l\'image {imageRef}…', {'imageRef': imageRef}));
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
      stderr.writeln(tr('scan: échec de la génération du SBOM de {imageRef} (code {code}).', {'imageRef': imageRef, 'code': code}));
      await quit(1);
    }
  }

  LayeredSbomSet? layerSet;
  if (perLayer) {
    layerSet = LayeredSbomSet.load(sbomFile);
    if (layerSet == null || layerSet.layers.isEmpty) {
      stderr.writeln(tr('scan: {sbomFile} ne porte aucune information de couche — produire le SBOM avec --per-layer (ou utiliser --image).', {'sbomFile': sbomFile}));
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
            '(${tr('par couche')}) ──────────────────────────');
      }
      for (final l in layerSet.layers) {
        if (l.path == null) continue;
        final found = await runScannerCached(s, l.path!);
        if (found == null) continue;
        for (final v in found) {
          v['layer'] = l.index;
        }
        (vulns ??= []).addAll(found);
      }
    } else {
      vulns = await runScannerCached(s, sbomFile);
      if (vulns != null && layerSet != null) {
        final unknown = attributeLayers(vulns, layerSet);
        if (unknown > 0 && !quiet) {
          stderr.writeln(tr('  {unknown} résultat(s) sans couche d\'origine connue (paquet absent du SBOM global).', {'unknown': unknown}));
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

  // Politique : VEX, CVE ignorées, référence (avant l'enrichissement, pour ne
  // pas interroger le réseau pour des CVE écartées).
  final now = DateTime.now();
  final policy = _applyScanPolicy(resultsByScanner,
      vex: vexDoc, ignore: ignoreList, baseline: baseline, now: now);
  final ignoredCount = policy.ignored;
  final vexCount = policy.vex;
  final baselineCount = policy.baseline;
  final vexCarried = policy.vexCarried;
  if (policy.total > 0) {
    final note = <String>[
      if (vexCount > 0)
        tr('{vexCount} écartée(s) par VEX', {'vexCount': vexCount}),
      if (ignoredCount > 0)
        tr('{ignoredCount} ignorée(s) (--ignore)', {'ignoredCount': ignoredCount}),
      if (baselineCount > 0)
        tr('{baselineCount} déjà connue(s) (--baseline)', {'baselineCount': baselineCount}),
    ];
    if (note.isNotEmpty) {
      final msg = tr('scan : {note}.', {'note': note.join(', ')});
      if (quiet) {
        stderr.writeln(msg);
      } else {
        stdout.writeln(msg);
      }
    }
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

  final vexOutPath = args['vex-out'] as String?;
  if (vexOutPath != null) {
    final purls = _purlIndex(sbomFile);
    final seen = <String>{};
    final statements = <VexStatement>[...vexCarried.values];
    for (final s in scanners) {
      for (final v in resultsByScanner[s] ?? const <Map<String, dynamic>>[]) {
        final id = '${v['id']}';
        final pkg = '${v['package']}';
        if (!seen.add('$id|$pkg')) continue;
        final fixed = [
          for (final f in (v['fixedVersions'] as List? ?? const [])) '$f'
        ];
        statements.add(VexStatement(
          vulnId: id,
          products: [purls[pkg] ?? 'pkg:generic/$pkg'],
          status: 'affected',
          actionStatement: fixed.isEmpty
              ? null
              : tr('Mettre à jour vers {versions}.',
                  {'versions': fixed.join(tr(' ou '))}),
        ));
      }
    }
    final author = args['vex-author'] as String;
    final doc = switch (args['vex-format']) {
      'cyclonedx' => buildCycloneDxVex(
          statements: statements, author: author, toolVersion: _version),
      'csaf' => buildCsafVex(
          statements: statements, author: author, toolVersion: _version),
      _ => buildOpenVex(
          statements: statements, author: author, toolVersion: _version),
    };
    await File(vexOutPath).writeAsString('${encodeVex(doc)}\n');
    stderr.writeln(tr('VEX écrit → {vexOutPath} ({statements} déclaration(s))', {'vexOutPath': vexOutPath, 'statements': statements.length}));
  }

  // Entrée commune du JSON et des rapports (un seul générateur de rapport :
  // `report` et la GUI relisent le même contenu).
  final needInput = format == 'json' || isReport;
  ReportInput? liveInput;
  if (needInput) {
    liveInput = ReportInput(
      results: {
        for (final k in reportScanners) k: resultsByScanner[k],
      },
      exploit: exploitById,
      toolVersions: {
        'sbom-generator': _version,
        for (final k in scanners)
          if (resultsByScanner.containsKey(k))
            _scannerTitle(k):
                await _scannerVersion(k) ?? tr('inconnue'),
      },
      layers: layerSet?.layers ?? const [],
      layerScanMode: layerSet != null ? layerScan : null,
      targets: [
        if (imageRef != null)
          'image $imageRef'
        else if (packageRef != null)
          tr('paquet {packageRef}', {'packageRef': packageRef})
        else
          sbomFile,
      ],
      vex: vexDoc?.statements ?? const [],
      vexSuppressed: policy.hits,
      generatedAt: DateTime.now(),
    );
  }

  if (format == 'json') {
    final doc = _buildScanJson(
      input: liveInput!,
      target: imageRef ?? packageRef ?? sbomFile,
      ignored: ignoredCount,
      vex: vexCount,
      baselineKnown: baselineCount,
    );
    final text = const JsonEncoder.withIndent('  ')
        .convert(jsonDecode(jsonEncode(doc, toEncodable: (o) => '$o')));
    if (outputPath != null) {
      await File(outputPath).writeAsString('$text\n');
      stderr.writeln(
          tr('JSON écrit → {outputPath}', {'outputPath': outputPath}));
    } else {
      print(text);
    }
  }

  if (format == 'sarif') {
    final sarif = _buildSarifReport(
        resultsByScanner, imageRef ?? packageRef ?? sbomFile, exploitById);
    final json = const JsonEncoder.withIndent('  ').convert(sarif);
    if (outputPath != null) {
      await File(outputPath).writeAsString(json);
      stderr.writeln(
          tr('SARIF écrit → {outputPath}', {'outputPath': outputPath}));
    } else {
      print(json);
    }
  }

  if (isReport) {
    if (resultsByScanner.isEmpty) {
      stderr.writeln(tr('scan: aucun scanner n\'a produit de résultat — rapport non généré.'));
      await quit(1);
    }
    final compareWith = args['compare-with'] as String?;
    ReportInput? compareInput;
    if (compareWith != null) {
      compareInput = _loadReportInputOrExit('scan', compareWith);
    }
    final gen = ScanReportGenerator.fromInput(
      liveInput!,
      threshold: args['report-severity'] as String,
      compareWith: compareInput,
      sbomPath: liveInput.targets.first,
    );
    _printSeverityAlerts(gen, colorMode, exploitById);
    await _writeScanReport(format, outputPath!, gen);
    // Un rapport produit n'est pas un échec, quel que soit le nombre de CVE.
    await quit(0);
  }

  if (failOn != null) {
    final min = severityRank(failOn);
    final failing = resultsByScanner.values
        .expand((l) => l)
        .where((v) => severityRank('${v['severity']}') >= min)
        .length;
    await quit(failing > 0 ? 1 : 0);
  }
  await quit(totalShown > 0 ? 1 : 0);
}

/// Résultat de [_applyScanPolicy] : nombre de CVE écartées par cause, et
/// déclarations « non affecté » reprises du VEX d'entrée.
class _PolicyOutcome {
  int ignored = 0, vex = 0, baseline = 0;
  final vexCarried = <String, VexStatement>{};
  final hits = <VexHit>[];
  int get total => ignored + vex + baseline;
}

/// Écarte des résultats de scan (modifiés en place) les CVE ignorées
/// (`--ignore`), déclarées non affectées/corrigées par VEX (`--vex`) ou déjà
/// présentes dans la référence (`--baseline`).
_PolicyOutcome _applyScanPolicy(
  Map<String, List<Map<String, dynamic>>> resultsByScanner, {
  VexDocument? vex,
  IgnoreList? ignore,
  Baseline? baseline,
  required DateTime now,
}) {
  final out = _PolicyOutcome();
  if (vex == null && ignore == null && baseline == null) return out;
  for (final s in resultsByScanner.keys.toList()) {
    final kept = <Map<String, dynamic>>[];
    for (final v in resultsByScanner[s]!) {
      final id = '${v['id']}';
      final pkg = '${v['package']}';
      if (ignore?.match(id, pkg, now) != null) {
        out.ignored++;
        continue;
      }
      if (vex != null) {
        final (n, ver) = splitPackage(pkg);
        final st = vex.find(id, n, ver);
        if (st != null && st.suppresses) {
          out.vex++;
          if (out.vexCarried['${st.vulnId}|$pkg'] == null) {
            out.hits.add(VexHit(id, pkg, st));
          }
          out.vexCarried['${st.vulnId}|$pkg'] = VexStatement(
              vulnId: id,
              products: st.products.isEmpty ? [pkg] : st.products,
              status: st.status,
              justification: st.justification,
              impactStatement: st.impactStatement);
          continue;
        }
      }
      if (baseline != null && baseline.contains(id, pkg)) {
        out.baseline++;
        continue;
      }
      kept.add(v);
    }
    resultsByScanner[s] = kept;
  }
  return out;
}

/// Charge un document VEX ; erreur d'usage (code 1) si illisible.
VexDocument _loadVexOrExit(String cmd, String path) {
  try {
    return VexDocument.parse(
        jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>);
  } on FileSystemException {
    stderr.writeln(tr('{cmd}: fichier VEX introuvable : {path}', {'cmd': cmd, 'path': path}));
  } on FormatException catch (e) {
    stderr.writeln('$cmd: --vex $path: ${e.message}');
  } catch (e) {
    stderr.writeln(tr('{cmd}: --vex {path} : JSON illisible ({e})', {'cmd': cmd, 'path': path, 'e': e}));
  }
  exit(1);
}

/// Charge un fichier `--ignore` (avertissements et règles expirées sur
/// stderr) ; erreur d'usage (code 1) si introuvable.
IgnoreList _loadIgnoreOrExit(String cmd, String path) {
  final IgnoreList list;
  try {
    list = IgnoreList.load(path);
  } on FileSystemException {
    stderr.writeln(tr('{cmd}: fichier --ignore introuvable : {path}', {'cmd': cmd, 'path': path}));
    exit(1);
  }
  for (final w in list.warnings) {
    stderr.writeln('$cmd: --ignore : $w');
  }
  for (final e in list.expired(DateTime.now())) {
    stderr.writeln(tr('{cmd}: règle ignorée EXPIRÉE (ligne {line}) : {id}{package} — non appliquée.', {'cmd': cmd, 'line': e.line, 'id': e.id, 'package': e.package != null ? ' (${e.package})' : ''}));
  }
  return list;
}

/// Index `nom@version` → PURL des composants d'un SBOM (CycloneDX, SPDX 2,
/// SPDX 3), pour que les déclarations VEX visent des PURL.
Map<String, String> _purlIndex(String sbomFile) {
  final out = <String, String>{};
  try {
    final j = jsonDecode(File(sbomFile).readAsStringSync()) as Map;
    void walk(List? comps) {
      for (final c in comps ?? const []) {
        if (c is! Map) continue;
        final name = '${c['name'] ?? ''}';
        final ver =
            '${c['version'] ?? c['versionInfo'] ?? spdx3Prop(c, 'packageVersion') ?? ''}';
        String? purl = c['purl'] as String?;
        for (final r in (c['externalRefs'] as List? ?? const [])) {
          if (r is Map && r['referenceType'] == 'purl') {
            purl ??= r['referenceLocator'] as String?;
          }
        }
        for (final r in (c['externalIdentifier'] as List? ?? const [])) {
          if (r is Map &&
              (r['externalIdentifierType'] == 'purl' ||
                  r['externalIdentifierType'] == 'packageUrl')) {
            purl ??= r['identifier'] as String?;
          }
        }
        if (name.isNotEmpty && purl != null) out['$name@$ver'] = purl;
        walk(c['components'] as List?);
      }
    }

    walk(j['components'] as List?);
    walk(j['packages'] as List?);
    walk([
      for (final n in (j['@graph'] as List? ?? const []))
        if (n is Map && '${n['type']}'.endsWith('Package')) n
    ]);
  } catch (_) {}
  return out;
}

/// Résultats d'un scan au format JSON : sert de `--baseline`, de
/// `--compare-with` et d'entrée à la sous-commande `report` (qui relit aussi
/// les sessions de la GUI).
Map<String, dynamic> _buildScanJson({
  required ReportInput input,
  required String target,
  required int ignored,
  required int vex,
  required int baselineKnown,
}) {
  final bySeverity = <String, int>{};
  final findings = <Map<String, dynamic>>[];
  for (final e in input.results.entries) {
    for (final v in e.value ?? const <Map<String, dynamic>>[]) {
      final sev = '${v['severity']}';
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
      findings.add({
        'scanner': e.key,
        for (final f in v.entries)
          if (f.key != 'exploit') f.key: f.value,
      });
    }
  }
  return {
    'schema': 'sbom-generator/scan/v1',
    'generatedAt': DateTime.now().toUtc().toIso8601String(),
    'tool': 'sbom-generator $_version',
    'target': target,
    'scanners': [
      for (final e in input.results.entries)
        if (e.value != null) e.key,
    ],
    'summary': {
      'total': findings.length,
      'bySeverity': bySeverity,
      'vexSuppressed': vex,
      'ignored': ignored,
      'baselineKnown': baselineKnown,
    },
    'toolVersions': input.toolVersions,
    'exploit': {
      for (final e in input.exploit.entries)
        if (e.value.hasAnySignal) e.key: exploitToJson(e.value),
    },
    if (input.layers.isNotEmpty) ...{
      'layers': [for (final l in input.layers) layerToJson(l)],
      'layerScanMode': input.layerScanMode,
    },
    if (input.vex.isNotEmpty) 'vex': [for (final x in input.vex) vexToJson(x)],
    if (input.vexSuppressed.isNotEmpty)
      'vexSuppressed': [for (final h in input.vexSuppressed) hitToJson(h)],
    'findings': findings,
  };
}

/// Lit un fichier `scan --format json` ou une session de la GUI ; erreur
/// d'usage (code 1) sinon.
ReportInput _loadReportInputOrExit(String cmd, String path) {
  try {
    return ReportInput.decode(File(path).readAsStringSync());
  } on FileSystemException {
    stderr.writeln(
        tr('{cmd}: fichier introuvable : {path}', {'cmd': cmd, 'path': path}));
  } on FormatException catch (e) {
    stderr.writeln('$cmd: $path : ${e.message}');
  } catch (e) {
    stderr.writeln(tr('{cmd}: {path} : lecture impossible ({e})', {'cmd': cmd, 'path': path, 'e': e}));
  }
  exit(1);
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
  stdout.writeln('\n── ${tr('CVE par couche')} '
      '(${layerScan == 'each' ? tr('scan de chaque couche') : tr('rattachement au SBOM global')}) ──────────');
  stdout.writeln(
      '${tr('COUCHE').padRight(8)}  ${'DIGEST'.padRight(12)}  '
      '${'CVE'.padLeft(4)}  ${'CRIT'.padLeft(4)}  ${'HIGH'.padLeft(4)}  '
      '${tr('INSTRUCTION')}');
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
      ? tr(', dont {kevCount} au catalogue CISA KEV', {'kevCount': kevCount})
      : '';
  final summary = tr('→ {crit} CVE critique(s), {high} CVE High{kevSuffix}', {'crit': crit, 'high': high, 'kevSuffix': kevSuffix});
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
    stdout.writeln(tr('Rapport Markdown écrit → {outputPath}', {'outputPath': outputPath}));
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
    stdout.writeln(tr('Rapport AsciiDoc écrit → {adocPath}', {'adocPath': adocPath}));
    return;
  }

  try {
    final r = await renderAsciiDocToPdf(adocPath, outputPath);
    if (r.exitCode == 0) {
      stdout.writeln(tr('Rapport PDF écrit → {outputPath}', {'outputPath': outputPath}));
    } else {
      stderr.writeln(tr('scan: asciidoctor-pdf a échoué (code {exitCode}) : {trim}', {'exitCode': r.exitCode, 'trim': (r.stderr as String).trim()}));
      stderr.writeln(tr('scan: rapport AsciiDoc conservé → {adocPath}', {'adocPath': adocPath}));
    }
  } on ProcessException {
    stderr.writeln(tr('scan: asciidoctor-pdf introuvable — PDF non généré, rapport AsciiDoc conservé → {adocPath}', {'adocPath': adocPath}));
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
    stderr.writeln(tr('grype: introuvable ({message}). Installez-le ou omettez --scanner grype.', {'message': e.message}));
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln(tr('grype: erreur (code {exitCode}) : {stderr}', {'exitCode': result.exitCode, 'stderr': result.stderr}));
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
        // Type de paquet (rpm, deb, java-archive…) : colonne annexe du détail.
        if ('${artifact['type'] ?? ''}'.isNotEmpty) 'extra': artifact['type'],
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
    stderr.writeln(tr('grype: impossible de parser le JSON: {e}', {'e': e}));
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
    stderr.writeln(tr('osv-scanner: introuvable ({message}). Installez-le ou omettez --scanner osv.', {'message': e.message}));
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln(tr('osv-scanner: erreur (code {exitCode}) : {stderr}', {'exitCode': result.exitCode, 'stderr': result.stderr}));
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
            // Écosystème (Debian, npm, Maven…) : colonne annexe du détail.
            if ('${res['source']?['type'] ?? pkgInfo['ecosystem'] ?? ''}'
                .isNotEmpty)
              'extra': pkgInfo['ecosystem'] ?? res['source']?['type'],
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
    stderr.writeln(tr('osv-scanner: impossible de parser le JSON: {e}', {'e': e}));
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
    stderr.writeln(tr('trivy: introuvable ({message}). Installez-le ou omettez --scanner trivy.', {'message': e.message}));
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln(tr('trivy: erreur (code {exitCode}) : {stderr}', {'exitCode': result.exitCode, 'stderr': result.stderr}));
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
          // Titre de la CVE (description courte) : détail du rapport.
          if ('${v['Title'] ?? ''}'.isNotEmpty) 'extra': v['Title'],
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
    stderr.writeln(tr('trivy: impossible de parser le JSON: {e}', {'e': e}));
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
      stderr.writeln(tr('scan: enrichissement CVE indisponible ({e})', {'e': e}));
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
    filterDesc.write(tr('  Filtre : champ={field}', {'field': field}));
    if (after != null) {
      filterDesc.write(
          tr('  après={after}', {'after': _formatDate(after)}));
    }
    if (before != null) {
      filterDesc.write(tr('  avant={before}', {'before': _formatDate(before)}));
    }
  }
  stdout.writeln(tr('  {vulns} CVE(s) trouvée(s){filterDesc}', {'vulns': vulns.length, 'filterDesc': filterDesc}));

  if (vulns.isEmpty) return;

  const w0 = 10, w1 = 20, w2 = 30, w3 = 4, w4 = 10;
  final withLayer = vulns.any((v) => v['layer'] != null);
  final withContainer = vulns.any((v) => v['container'] != null);
  stdout.writeln('${tr('SÉVÉRITÉ').padRight(w0)}  '
      '${'CVE / ID'.padRight(w1)}  '
      '${tr('PAQUET').padRight(w2)}  ${'KEV'.padRight(w3)}  '
      '${'EPSS'.padRight(w4)}  '
      '${withLayer ? tr('PoC  COUCHE') : 'PoC'}'
      '${withContainer ? tr('  OBJET') : ''}');
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
  stdout.writeln(tr('sbom_generator scan – Analyser les CVE d\'un fichier SBOM avec filtre par date.\n\nUsage:\n  sbom-generator scan --sbom <fichier.cdx.json> [options]\n  sbom-generator scan --image <image> [--per-layer] [options]\n  sbom-generator scan --package <rpm|deb|tgz|zip|jar…> [--depth N] [options]\n\n{usage}\n\nExemples:\n  # Toutes les CVE grype depuis 2024\n  sbom-generator scan --sbom sbom.cdx.json --cve-after 2024-01-01\n\n  # CVE OSV-Scanner entre deux dates\n  sbom-generator scan --sbom sbom.cdx.json --scanner osv \\\n    --cve-after 2023-06-01 --cve-before 2024-01-01\n\n  # Tous les scanners, champ modification, CVE sans date incluses\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --cve-date-field modified --cve-after 2023-01-01 --include-undated\n\n  # Export SARIF (GitHub Code Scanning) vers un fichier\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --format sarif --output results.sarif\n\n  # Rapport de synthèse PDF (Grype + OSV-Scanner + Trivy)\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --format pdf --output scan-report.pdf\n\n  # Seulement les CVE activement exploitées (CISA KEV), triées par risque\n  sbom-generator scan --sbom sbom.cdx.json --scanner all \\\n    --only-kev --sort risk\n\n  # Prioriser : CVE avec une probabilité d\'exploitation EPSS ≥ 10 %\n  sbom-generator scan --sbom sbom.cdx.json --epss-min 0.1\n\n  # Hors-ligne : pas de requête réseau (KEV/EPSS/PoC seulement via Grype + cache)\n  sbom-generator scan --sbom sbom.cdx.json --no-enrich\n\n  # CVE par couche d\'une image (SBOM généré à la volée, un scan rattaché)\n  sbom-generator scan --image ./app.tar --per-layer --scanner all\n\n  # Idem, SBOM de chaque couche scanné (couches calculées en mode rootfs),\n  # rapport PDF avec section « Couches de l\'image »\n  sbom-generator scan --image nginx:latest --per-layer --layer-scan each \\\n    --layer-mode rootfs --scanner all -f pdf -o nginx-layers.pdf\n\n  # À partir d\'un jeu déjà produit par sbom-generator --per-layer\n  sbom-generator scan --sbom out/app.cdx.json --per-layer\n\n  # Scanner directement un RPM et les jars qu\'il contient (2 niveaux) ;\n  # chaque CVE indique l\'objet (rpm, jar…) qui contient le paquet vulnérable\n  sbom-generator scan --package app-1.0-1.x86_64.rpm --depth 2 --scanner all\n\n  # Archive : tout ce qu\'elle contient, sans limite de profondeur\n  sbom-generator scan --package release.tar.gz --depth all\n\nEnrichissement : chaque CVE est complétée par CISA KEV (exploitée dans la\nnature), EPSS (probabilité d\'exploitation à 30 jours), un signal PoC public\net le sous-score d\'exploitabilité CVSS. Actif par défaut ; --no-enrich (ou\nSBOMGEN_OFFLINE=1) le désactive, --no-poc ne coupe que la source tierce.\n\nEn --format markdown/asciidoc/pdf, chaque CVE Critical (rouge) et High\n(orange) est aussi listée sur stdout, une ligne par CVE unique\n(dédupliquée entre scanners), avec les marqueurs [KEV] / EPSS / [PoC] —\nutile pendant un build. --color auto par défaut (couleur si stdout est un\nterminal et NO_COLOR non défini) ; --color always force la couleur\nderrière un pipe.\n\nCodes de retour:\n  text / sarif :\n    0  Aucune CVE dans la plage demandée\n    1  Au moins une CVE trouvée (ou erreur de scanner)\n  markdown / asciidoc / pdf :\n    0  Rapport produit (quel que soit le nombre de CVE ; pour pdf, le\n       .adoc est conservé si asciidoctor-pdf est absent)\n    1  Aucun scanner n\'a produit de résultat, ou --output manquant\n', {'usage': parser.usage}));
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
                      tr('{id} — sévérité {severity}', {'id': id, 'severity': severity})
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
          'text': tr('Paquet vulnérable : {pkg} (sévérité {severity}){layer}', {
                'pkg': pkg,
                'severity': severity,
                'layer': layer != null ? tr(' — couche {layer}', {'layer': layer}) : '',
              }),
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
      if (_licenseOverrideFor(pkg, overrides) case final lic?)
        pkg.copyWith(license: lic)
      else
        pkg,
  ];
}

/// Licence de substitution d'un paquet : par nom, puis par PURL sans version
/// (`pkg:maven/org.yaml/snakeyaml`), puis, pour Maven, par
/// `groupId:artifactId`.
String? _licenseOverrideFor(Package pkg, Map<String, String> overrides) {
  if (overrides[pkg.name] case final lic?) return lic;
  final purl = pkg.purl.split('?').first;
  final bare = purl.split('@').first;
  if (overrides[bare] case final lic?) return lic;
  final m = RegExp(r'^pkg:maven/([^/]+)/([^/]+)$').firstMatch(bare);
  if (m != null) {
    final ga = '${Uri.decodeComponent(m.group(1)!)}:'
        '${Uri.decodeComponent(m.group(2)!)}';
    return overrides[ga];
  }
  return null;
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

// ── Sous-commande report ──────────────────────────────────────────────────────

Future<void> _runReport(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('input',
        abbr: 'i',
        mandatory: true,
        help: tr('Résultats de scan : fichier `scan --format json` ou session de\nla GUI (« Enregistrer la session… »).'))
    ..addOption('output',
        abbr: 'o',
        mandatory: true,
        help: tr('Fichier du rapport (.pdf, .adoc ou .md selon --format).'))
    ..addOption('format',
        abbr: 'f',
        allowed: ['pdf', 'asciidoc', 'markdown'],
        defaultsTo: 'pdf',
        help: tr('Format du rapport.'))
    ..addOption('severity',
        abbr: 's',
        allowed: ScanReportGenerator.thresholds,
        defaultsTo: 'all',
        help: tr('Ne garder que les CVE dont la pire sévérité atteint ce seuil\n(critical, high, medium), plus celles du catalogue CISA KEV.'))
    ..addOption('compare-with',
        help: tr('Section « Tendance » par rapport à un autre fichier de résultats.'))
    ..addOption('vex',
        help: tr('Document VEX supplémentaire (OpenVEX / CSAF / CycloneDX) : les CVE\n« non affectées » / « corrigées » sont écartées du rapport.'))
    ..addFlag('no-vex',
        negatable: false,
        help: tr('Ignorer les déclarations VEX embarquées dans le fichier.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.'));

  void usage() => stdout.writeln(tr('sbom_generator report – Rapport de vulnérabilités (synthèse inter-scanners,\nremédiation, tendance, VEX, détail des CVE) à partir de résultats déjà obtenus,\nsans relancer les scanners. C\'est le même rapport que `scan --format pdf` et que\nl\'export du tableau de bord de la GUI.\n\nUsage:\n  sbom-generator report -i resultats.json -o rapport.pdf\n  sbom-generator report -i session.json -s high --compare-with ancien.json -o rapport.pdf\n\n{usage}\n', {'usage': parser.usage}));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('report: ${_argError(e.message)}');
    usage();
    exit(1);
  }
  if (!(args['help'] as bool)) _requireMandatory(parser, args, 'report', usage);
  if (args['help'] as bool) {
    usage();
    exit(0);
  }

  var input = _loadReportInputOrExit('report', args['input'] as String);
  final extraVex = args['vex'] as String?;
  final noVex = args['no-vex'] as bool;
  if (extraVex != null || noVex) {
    input = ReportInput(
      results: input.results,
      exploit: input.exploit,
      toolVersions: input.toolVersions,
      layers: input.layers,
      layerScanMode: input.layerScanMode,
      targets: input.targets,
      vex: [
        if (!noVex) ...input.vex,
        if (extraVex != null) ..._loadVexOrExit('report', extraVex).statements,
      ],
      vexSuppressed: noVex ? const [] : input.vexSuppressed,
      generatedAt: input.generatedAt,
    );
  }
  final cmp = args['compare-with'] as String?;
  final gen = ScanReportGenerator.fromInput(
    input,
    threshold: args['severity'] as String,
    compareWith: cmp == null ? null : _loadReportInputOrExit('report', cmp),
    extraTools: {'sbom-generator': _version},
    generatedAt: DateTime.now(),
  );
  await _writeScanReport(
      args['format'] as String, args['output'] as String, gen);
}

// ── Sous-commande vex ─────────────────────────────────────────────────────────

Future<void> _runVex(List<String> arguments) async {
  final parser = ArgParser()
    ..addMultiOption('cve',
        abbr: 'c',
        help: tr('Identifiant(s) de vulnérabilité (CVE-…, GHSA-…). Répétable.'))
    ..addMultiOption('product',
        abbr: 'p',
        help: tr('Produit(s) concerné(s) : PURL, `nom` ou `nom@version`.\nRépétable ; omis = tous les produits.'))
    ..addOption('status',
        abbr: 's',
        allowed: vexStatuses.toList(),
        mandatory: true,
        help: tr('État de la vulnérabilité pour ces produits.'))
    ..addOption('justification',
        allowed: openVexJustifications.toList(),
        help: tr('Obligatoire pour not_affected (vocabulaire OpenVEX).'))
    ..addOption('impact-statement',
        help: tr('Explication libre (pourquoi non affecté).'))
    ..addOption('action-statement',
        help: tr('Action recommandée (pour affected).'))
    ..addOption('author',
        defaultsTo: 'sbom-generator',
        help: tr('Auteur du document.'))
    ..addOption('append',
        help: tr('Document VEX existant (OpenVEX, CycloneDX ou CSAF) auquel ajouter les\ndéclarations ; le résultat est réécrit dans -o.'))
    ..addOption('format',
        abbr: 'f',
        allowed: ['openvex', 'cyclonedx', 'csaf'],
        help: tr('Format du document produit : openvex (défaut), cyclonedx ou csaf\n(CSAF 2.0 VEX), ou celui de --append.'))
    ..addOption('output',
        abbr: 'o',
        help: tr('Fichier de sortie (stdout si omis).'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.'));

  void usage() => stdout.writeln(tr('sbom_generator vex – Crée ou complète un document VEX (OpenVEX / CycloneDX / CSAF).\n\nUsage:\n  sbom-generator vex --cve CVE-2024-1234 --product pkg:npm/foo@1.0.0 \\\n    --status not_affected --justification vulnerable_code_not_in_execute_path \\\n    --impact-statement "Fonction non appelée" -o vex.json\n\n{usage}\n\nLe document produit s\'utilise avec `scan --vex vex.json`.\n', {'usage': parser.usage}));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('vex: ${_argError(e.message)}');
    usage();
    exit(1);
  }
  if (!(args['help'] as bool)) _requireMandatory(parser, args, 'vex', usage);
  if (args['help'] as bool) {
    usage();
    exit(0);
  }
  final cves = args['cve'] as List<String>;
  if (cves.isEmpty) {
    stderr.writeln(tr('vex: au moins un --cve est requis.'));
    exit(1);
  }
  final status = args['status'] as String;
  final justification = args['justification'] as String?;
  if (status == 'not_affected' &&
      justification == null &&
      args['impact-statement'] == null) {
    stderr.writeln(tr('vex: not_affected exige --justification (ou --impact-statement).'));
    exit(1);
  }

  final statements = <VexStatement>[];
  String? appendedFormat;
  final appendPath = args['append'] as String?;
  if (appendPath != null) {
    try {
      final j = jsonDecode(File(appendPath).readAsStringSync())
          as Map<String, dynamic>;
      statements.addAll(VexDocument.parse(j).statements);
      appendedFormat = j['bomFormat'] == 'CycloneDX'
          ? 'cyclonedx'
          : isCsafVex(j)
              ? 'csaf'
              : 'openvex';
    } on FileSystemException {
      stderr.writeln(tr('vex: fichier introuvable : {appendPath}', {'appendPath': appendPath}));
      exit(1);
    } on FormatException catch (e) {
      stderr.writeln('vex: --append : ${e.message}');
      exit(1);
    }
  }
  for (final id in cves) {
    statements.add(VexStatement(
      vulnId: id,
      products: args['product'] as List<String>,
      status: status,
      justification: justification,
      impactStatement: args['impact-statement'] as String?,
      actionStatement: args['action-statement'] as String?,
    ));
  }
  final format = (args['format'] as String?) ?? appendedFormat ?? 'openvex';
  final author = args['author'] as String;
  final doc = switch (format) {
    'cyclonedx' => buildCycloneDxVex(
        statements: statements, author: author, toolVersion: _version),
    'csaf' => buildCsafVex(
        statements: statements, author: author, toolVersion: _version),
    _ => buildOpenVex(
        statements: statements, author: author, toolVersion: _version),
  };
  final text = '${encodeVex(doc)}\n';
  final out = args['output'] as String?;
  if (out == null) {
    stdout.write(text);
  } else {
    await File(out).writeAsString(text);
    stderr.writeln(tr('VEX écrit → {out} ({statements} déclaration(s))', {'out': out, 'statements': statements.length}));
  }
}

// ── Sous-commande convert ─────────────────────────────────────────────────────

Future<void> _runConvert(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('input',
        abbr: 'i',
        mandatory: true,
        help: tr('Fichier SBOM source (CycloneDX JSON ou SPDX JSON/JSON-LD).'))
    ..addOption('output',
        abbr: 'o',
        mandatory: true,
        help: tr('Fichier de sortie. Avec plusieurs formats (-f a,b) : chemin de base.'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'cyclonedx',
        help: tr('Format(s) cible(s), séparés par des virgules.\n  cyclonedx  spdx  spdx3  json  markdown  asciidoc  html  csv'))
    ..addOption('name',
        abbr: 'n',
        help: tr('Nom du document SBOM de sortie (remplace celui du fichier source).'))
    ..addOption('supplier',
        help: tr('Fournisseur par défaut des composants sans éditeur dans le SBOM\nsource. N\'écrase jamais un fournisseur déjà présent.'))
    ..addOption(
      'cyclonedx-version',
      defaultsTo: '1.6',
      allowed: _validCycloneDxVersions,
      help: tr('Version CycloneDX cible quand -f inclut "cyclonedx" (défaut : 1.6).'),
    )
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('convert: ${_argError(e.message)}');
    _printConvertUsage(parser);
    exit(1);
  }
  if (!(args['help'] as bool)) {
    _requireMandatory(
        parser, args, 'convert', () => _printConvertUsage(parser));
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
      stderr.writeln(tr('convert: format inconnu "{f}". Valides : {_validFormats}', {'f': f, '_validFormats': _validFormats.join(', ')}));
      exit(1);
    }
  }

  if (!await File(inputPath).exists()) {
    stderr.writeln(tr('convert: fichier introuvable : {inputPath}', {'inputPath': inputPath}));
    exit(1);
  }

  final Map<String, dynamic> json;
  try {
    json = await SbomReader.loadJson(inputPath);
  } catch (e) {
    stderr.writeln(tr('convert: impossible de lire le JSON : {e}', {'e': e}));
    exit(1);
  }

  final reader = SbomReader();
  final format = SbomReader.detectFormat(json);
  if (format == SbomFormat.unknown) {
    stderr.writeln(tr('convert: format SBOM non reconnu dans {inputPath}', {'inputPath': inputPath}));
    stderr.writeln(tr('  Formats supportés : CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD'));
    exit(1);
  }

  List<Package> packages;
  try {
    packages = reader.read(json);
  } catch (e) {
    stderr.writeln(
        tr('convert: erreur de lecture : {e}', {'e': e}));
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
  print(tr('Conversion : {inputPath} ({formatLabel}, {packages} composant(s))', {'inputPath': inputPath, 'formatLabel': formatLabel, 'packages': packages.length}));

  for (final fmt in formats) {
    final outPath = _outputPathFor(outputPath, formats, fmt);
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
      stderr.writeln(tr('convert: échec de l\'écriture ({fmt}) : {e}', {'fmt': fmt, 'e': e}));
      exit(1);
    }
    final sz = await File(outPath).length();
    print('→ $outPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
  }
}

void _printConvertUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator convert – Convertit un fichier SBOM vers un ou plusieurs formats.\n\nUsage:\n  sbom_generator convert -i source.cdx.json -f spdx -o output.spdx.json\n  sbom_generator convert -i source.spdx.json -f cyclonedx,csv -o output\n\nFormats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\nFormats cible supportés  : cyclonedx, spdx, spdx3, json, markdown, asciidoc, html, csv\n\n{usage}\n', {'usage': parser.usage}));
}

// ── Sous-commande licenses ─────────────────────────────────────────────────────

Future<void> _runLicenses(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('input',
        abbr: 'i',
        mandatory: true,
        help: tr('Fichier SBOM source (CycloneDX JSON ou SPDX JSON/JSON-LD).'))
    ..addOption('output',
        abbr: 'o',
        help: tr('Fichier de sortie (ex : licences.adoc). Facultatif avec --format json (sortie standard).'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'asciidoc',
        allowed: ['asciidoc', 'adoc', 'markdown', 'html', 'csv', 'json'],
        help: tr('Format du rapport.'))
    ..addOption('name',
        abbr: 'n',
        help: tr('Nom du document (remplace celui du fichier source).'))
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('licenses: ${_argError(e.message)}');
    _printLicensesUsage(parser);
    exit(1);
  }
  if (!(args['help'] as bool)) {
    _requireMandatory(
        parser, args, 'licenses', () => _printLicensesUsage(parser));
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
    stderr.writeln(tr('licenses: --output est obligatoire (sauf avec --format json).'));
    exit(1);
  }

  if (!await File(inputPath).exists()) {
    stderr.writeln(tr('licenses: fichier introuvable : {inputPath}', {'inputPath': inputPath}));
    exit(1);
  }

  final Map<String, dynamic> json;
  try {
    json = await SbomReader.loadJson(inputPath);
  } catch (e) {
    stderr.writeln(tr('licenses: impossible de lire le JSON : {e}', {'e': e}));
    exit(1);
  }

  final reader = SbomReader();
  final sbomFormat = SbomReader.detectFormat(json);
  if (sbomFormat == SbomFormat.unknown) {
    stderr.writeln(tr('licenses: format SBOM non reconnu dans {inputPath}', {'inputPath': inputPath}));
    stderr.writeln(tr('  Formats supportés : CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD'));
    exit(1);
  }

  final List<Package> packages;
  try {
    packages = reader.read(json);
  } catch (e) {
    stderr.writeln(
        tr('licenses: erreur de lecture : {e}', {'e': e}));
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
  print(tr('Rapport de licences : {inputPath} ({packages} composant(s))', {'inputPath': inputPath, 'packages': packages.length}));

  try {
    await generator.writeToFile(packages, outputPath,
        documentName: name, format: format);
  } catch (e) {
    stderr.writeln(tr('licenses: échec de l\'écriture : {e}', {'e': e}));
    exit(1);
  }

  final sz = await File(outputPath).length();
  print('→ $outputPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
}

void _printLicensesUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator licenses – Génère un rapport de licences à partir d\'un fichier SBOM\n(AsciiDoc par défaut ; Markdown, HTML, CSV ou JSON avec --format).\n\nLe rapport regroupe les paquets par licence, avec un résumé et des\navertissements pour les licences copyleft (GPL/AGPL/LGPL/MPL/EPL/CDDL/CPL/EUPL)\net les paquets sans licence détectée.\n\nUsage:\n  sbom_generator licenses -i sbom.cdx.json -o licences.adoc\n  sbom_generator licenses -i sbom.spdx.json -o licences.adoc -n "Mon projet"\n  sbom_generator licenses -i sbom.cdx.json -f html -o licences.html\n  sbom_generator licenses -i sbom.cdx.json -f json        # JSON sur stdout\n\nFormats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\n\n{usage}\n', {'usage': parser.usage}));
}

// ── Sous-commande cra ─────────────────────────────────────────────────────────

Future<void> _runCra(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('sbom',
        abbr: 's',
        mandatory: true,
        help: tr('Fichier SBOM à évaluer (CycloneDX JSON ou SPDX JSON).'))
    ..addOption('config',
        abbr: 'c',
        help: tr('Fichier de métadonnées fabricant/produit (clé: valeur par ligne). Défaut : ./cra.yaml s\'il existe.'))
    ..addOption('manufacturer',
        help: tr('Nom du fabricant (surcharge --config).'))
    ..addOption('product', help: tr('Nom du produit.'))
    ..addOption('product-version',
        help: tr('Version du produit.'))
    ..addOption('support-until',
        help: tr('Date de fin de support (AAAA-MM-JJ).'))
    ..addOption('vuln-contact',
        help: tr('Adresse (e-mail ou URL) de signalement des vulnérabilités.'))
    ..addOption('cvd-policy-url',
        help: tr('URL de la politique de divulgation coordonnée.'))
    ..addFlag('scan',
        defaultsTo: true,
        help: tr('Lancer une analyse de vulnérabilités (grype/osv/trivy) pour évaluer l\'inventaire et les correctifs. --no-scan pour s\'en passer.'))
    ..addOption('scanner',
        abbr: 'S',
        defaultsTo: 'grype',
        help: tr('Scanner(s) : grype (défaut), osv, trivy, all.'))
    ..addOption('vex',
        help: tr('Document VEX (OpenVEX / CycloneDX) : les CVE "not_affected" ou\n"fixed" sont écartées de l\'inventaire des vulnérabilités.'))
    ..addOption('ignore',
        help: tr('Fichier de CVE ignorées (voir `scan --help`) : règles\njustifiées et datées, écartées de l\'inventaire.'))
    ..addFlag('enrich',
        defaultsTo: true,
        help: tr('Enrichir les CVE (CISA KEV / EPSS). --no-enrich pour rester hors-ligne.'))
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'pdf',
        allowed: ['pdf', 'asciidoc', 'json'],
        help: tr('Format de sortie : pdf (défaut), asciidoc, json.'))
    ..addOption('output',
        abbr: 'o',
        help: tr('Fichier de sortie. Requis pour pdf/asciidoc ; json sur stdout si omis.'))
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('cra: ${_argError(e.message)}');
    _printCraUsage(parser);
    exit(1);
  }
  if (!(args['help'] as bool)) {
    _requireMandatory(parser, args, 'cra', () => _printCraUsage(parser));
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
    stderr.writeln(tr('cra: fichier SBOM introuvable : {sbomFile}', {'sbomFile': sbomFile}));
    exit(1);
  }
  if ((format == 'pdf' || format == 'asciidoc') && outputPath == null) {
    stderr.writeln(tr('cra: --output <fichier> est requis pour --format {format}.', {'format': format}));
    exit(1);
  }

  final Map<String, dynamic> sbomJson;
  try {
    sbomJson = await SbomReader.loadJson(sbomFile);
  } catch (e) {
    stderr.writeln(tr('cra: impossible de lire le SBOM : {e}', {'e': e}));
    exit(1);
  }
  if (SbomReader.detectFormat(sbomJson) == SbomFormat.unknown) {
    stderr.writeln(tr('cra: format SBOM non reconnu (CycloneDX / SPDX attendu).'));
    exit(1);
  }

  // Métadonnées : cra.yaml (ou ./cra.yaml par défaut) puis surcharge CLI.
  var meta = const CraMetadata();
  final configPath = args['config'] as String? ??
      (await File('cra.yaml').exists() ? 'cra.yaml' : null);
  if (configPath != null) {
    if (!await File(configPath).exists()) {
      stderr.writeln(tr('cra: fichier de config introuvable : {configPath}', {'configPath': configPath}));
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
      }[s]!] = await _scannerVersion(s) ?? tr('inconnue');
    }
    if (scanResults.isEmpty) {
      stderr.writeln(tr('cra: aucun scanner disponible — rapport produit sans inventaire de vulnérabilités (utilisez --no-scan pour l\'assumer).'));
      scanResults = null;
    } else {
      final vexPath = args['vex'] as String?;
      final ignorePath = args['ignore'] as String?;
      final policy = _applyScanPolicy(
        scanResults,
        vex: vexPath != null ? _loadVexOrExit('cra', vexPath) : null,
        ignore:
            ignorePath != null ? _loadIgnoreOrExit('cra', ignorePath) : null,
        now: DateTime.now(),
      );
      if (policy.total > 0) {
        stderr.writeln(tr('cra : {vex} CVE écartée(s) par VEX, {ignored} ignorée(s).', {'vex': policy.vex, 'ignored': policy.ignored}));
      }
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
      stdout.writeln(tr('Rapport CRA (JSON) écrit → {outputPath}', {'outputPath': outputPath}));
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
    stdout.writeln(tr('Rapport CRA (AsciiDoc) écrit → {adocPath}', {'adocPath': adocPath}));
  } else {
    try {
      final r = await renderAsciiDocToPdf(adocPath, outputPath);
      if (r.exitCode == 0) {
        stdout.writeln(tr('Rapport CRA (PDF) écrit → {outputPath}', {'outputPath': outputPath}));
      } else {
        stderr.writeln(tr('cra: asciidoctor-pdf a échoué (code {exitCode}) — AsciiDoc conservé → {adocPath}', {'exitCode': r.exitCode, 'adocPath': adocPath}));
      }
    } on ProcessException {
      stderr.writeln(tr('cra: asciidoctor-pdf introuvable — PDF non généré, AsciiDoc conservé → {adocPath}', {'adocPath': adocPath}));
    }
  }

  final v = gen.verdict;
  stdout.writeln(
      tr('Verdict (périmètre vérifié) : ') +
          switch (v) {
            CraStatus.ok => tr('conforme'),
            CraStatus.partial =>
              tr('conforme avec réserves'),
            CraStatus.fail => tr('NON conforme ({blockers} point(s) bloquant(s))', {'blockers': gen.blockers.length}),
            CraStatus.na => tr('non évalué'),
          });
  exit(v == CraStatus.fail ? 2 : 0);
}

void _printCraUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator cra – Rapport de conformité Cyber Resilience Act (UE 2024/2847).\n\nPérimètre : éléments vérifiables automatiquement uniquement — format et\ncomplétude du SBOM (Annexe I §2 point 1, BSI TR-03183-2, éléments minimaux\nNTIA), inventaire des vulnérabilités connues et disponibilité des correctifs\n(Annexe I §2 points 1-2), vulnérabilités activement exploitées (art. 14).\nLes autres obligations du CRA relèvent du fabricant. Ce rapport n\'est pas une\ndéclaration de conformité.\n\nUsage:\n  sbom-generator cra --sbom sbom.cdx.json --format pdf -o rapport-cra.pdf\n  sbom-generator cra --sbom sbom.cdx.json --config cra.yaml -o rapport-cra.pdf\n  sbom-generator cra --sbom sbom.cdx.json --no-scan --format json\n\nFichier cra.yaml (toutes les clés sont facultatives) :\n  manufacturer: "ACME Corp"\n  product: "WidgetOS"\n  product_version: "3.2.1"\n  support_until: "2030-12-31"\n  vulnerability_contact: "security@acme.example"\n  cvd_policy_url: "https://acme.example/security/policy"\n\n{usage}\n\nCodes de retour : 0 = conforme / conforme avec réserves, 2 = non conforme\n(au moins un point bloquant sur le périmètre vérifié).\n', {'usage': parser.usage}));
}

// ── Sous-commande validate ────────────────────────────────────────────────────

Future<void> _runValidate(List<String> arguments) async {
  final parser = ArgParser()
    ..addFlag('strict',
        defaultsTo: false,
        negatable: false,
        help: tr('En mode strict, les champs recommandés (mais non obligatoires) génèrent aussi des erreurs.'))
    ..addFlag('schema',
        defaultsTo: true,
        help: tr('Valide aussi le document par rapport au schéma JSON officiel\n(CycloneDX 1.4–1.7, SPDX 2.3, SPDX 3.0), embarqué dans le\nprogramme. --no-schema : contrôles structurels seuls.\nLes fichiers SPDX 3.0 générés avant la 1.10.5 (ancien format)\ndonnent un avertissement.'))
    ..addOption('format',
        abbr: 'f',
        allowed: ['text', 'json'],
        defaultsTo: 'text',
        help: tr('Format du rapport : text (défaut) ou json (stdout, lisible par\nune machine).'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('validate: ${_argError(e.message)}');
    _printValidateUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printValidateUsage(parser);
    exit(0);
  }

  final files = args.rest;
  if (files.isEmpty) {
    stderr.writeln(tr('validate: au moins un fichier SBOM requis.'));
    _printValidateUsage(parser);
    exit(1);
  }

  final strict = args['strict'] as bool;
  final useSchema = args['schema'] as bool;
  final asJson = args['format'] == 'json';
  int totalErrors = 0;
  final report = <Map<String, dynamic>>[];

  void say(String line) {
    if (!asJson) print(line);
  }

  for (final path in files) {
    final entry = <String, dynamic>{'path': path};
    report.add(entry);
    if (!await File(path).exists()) {
      say(tr('{path} : ERREUR — fichier introuvable', {'path': path}));
      entry
        ..['valid'] = false
        ..['errors'] = [tr('fichier introuvable')];
      totalErrors++;
      continue;
    }

    final Map<String, dynamic> json;
    try {
      json = await SbomReader.loadJson(path);
    } catch (e) {
      say(tr('{path} : ERREUR — JSON invalide : {e}', {'path': path, 'e': e}));
      entry
        ..['valid'] = false
        ..['errors'] = [tr('JSON invalide : {e}', {'e': e})];
      totalErrors++;
      continue;
    }

    final errors = _validateSbom(json, strict: strict);
    final warnings = <String>[];
    final format = SbomReader.detectFormat(json);
    final label = switch (format) {
      SbomFormat.cyclonedx => 'CycloneDX ${json['specVersion'] ?? ''}',
      SbomFormat.spdx2 => 'SPDX ${json['spdxVersion'] ?? ''}',
      SbomFormat.spdx3 => 'SPDX 3.0 JSON-LD',
      SbomFormat.unknown => tr('format inconnu'),
    };

    String? schemaKey;
    if (useSchema) {
      schemaKey = SchemaValidator.schemaKeyFor(json);
      final schemaErrors =
          schemaKey == null ? null : SchemaValidator.validate(json);
      if (schemaErrors != null && schemaErrors.isNotEmpty) {
        final prefix = tr('[schéma] ');
        if (format == SbomFormat.spdx3) {
          // Le validateur ne localise pas les écarts du schéma SPDX 3.0
          // (oneOf / unevaluatedProperties) : un message unique et explicite.
          // Les fichiers produits avant la 1.10.5 (types `software:Package`,
          // licences en ligne…) n'étaient pas conformes : simple avertissement
          // pour ne pas invalider des SBOM déjà archivés.
          final legacy = ((json['@graph'] as List?) ?? const [])
              .any((n) => n is Map && n['type'] == 'software:Package');
          if (legacy && !strict) {
            warnings.add(
                '$prefix${tr('ancien format SPDX 3.0 non conforme au schéma officiel (généré avant la 1.10.5) : régénérez le SBOM.')}');
          } else {
            errors.add(
                '$prefix${tr('le document ne satisfait pas le schéma JSON officiel SPDX 3.0.')}');
          }
        } else {
          errors.addAll(schemaErrors.map((e) => '$prefix$e'));
        }
      } else if (schemaKey == null && format != SbomFormat.unknown) {
        warnings.add(tr('aucun schéma embarqué pour cette version : contrôle de schéma ignoré'));
      }
    }

    entry
      ..['format'] = label
      ..['schema'] = schemaKey
      ..['valid'] = errors.isEmpty
      ..['errors'] = errors
      ..['warnings'] = warnings;

    if (errors.isEmpty) {
      say('$path : OK ($label)');
    } else {
      say(tr('{path} : {label} — {errors} erreur(s) :', {'path': path, 'label': label, 'errors': errors.length}));
      for (final e in errors) {
        say('  ✗ $e');
      }
      totalErrors += errors.length;
    }
    for (final w in warnings) {
      say('  ⚠ $w');
    }
  }

  if (asJson) {
    print(const JsonEncoder.withIndent('  ').convert({
      'valid': totalErrors == 0,
      'errorCount': totalErrors,
      'files': report,
    }));
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
      errors.add(tr('Aucun indicateur de format reconnu. Attendu : bomFormat="CycloneDX", spdxVersion ou @context/@graph.'));
  }
  return errors;
}

void _validateCycloneDx(Map<String, dynamic> json, List<String> errors,
    {bool strict = false}) {
  if (json['bomFormat'] != 'CycloneDX') {
    errors.add(
        tr('bomFormat doit être "CycloneDX"'));
  }
  if (json['specVersion'] == null) {
    errors.add(tr('specVersion manquant'));
  }
  if (json['version'] == null && strict) {
    errors.add(tr('[strict] version manquant'));
  }
  if (json['serialNumber'] == null && strict) {
    errors.add(
        tr('[strict] serialNumber manquant'));
  }

  final components = json['components'];
  if (components != null && components is! List) {
    errors.add(tr('components doit être un tableau JSON'));
  } else if (components is List) {
    for (int i = 0; i < components.length; i++) {
      final c = components[i];
      if (c is! Map) continue;
      if (c['name'] == null || (c['name'] as String).isEmpty) {
        errors.add(tr('composant[{i}] : champ name manquant ou vide', {'i': i}));
      }
      if (c['type'] == null) {
        errors.add(tr('composant[{i}] ({name}) : champ type manquant', {'i': i, 'name': c['name'] ?? '?'}));
      }
      if (strict && c['version'] == null) {
        errors.add(tr('[strict] composant[{i}] ({name}) : version manquante', {'i': i, 'name': c['name'] ?? '?'}));
      }
    }
  }
}

void _validateSpdx2(Map<String, dynamic> json, List<String> errors,
    {bool strict = false}) {
  final ver = json['spdxVersion'] as String?;
  if (ver == null || !ver.startsWith('SPDX-')) {
    errors.add(tr('spdxVersion manquant ou invalide (attendu : SPDX-2.x)'));
  }
  if (json['SPDXID'] != 'SPDXRef-DOCUMENT') {
    errors.add(tr('SPDXID doit être "SPDXRef-DOCUMENT"'));
  }
  if (json['name'] == null) errors.add(tr('name manquant'));
  if (json['dataLicense'] == null) {
    errors.add(tr('dataLicense manquant'));
  }
  if (strict && json['creationInfo'] == null) {
    errors.add(
        tr('[strict] creationInfo manquant'));
  }

  final packages = json['packages'];
  if (packages is List) {
    for (int i = 0; i < packages.length; i++) {
      final p = packages[i] as Map?;
      if (p == null) continue;
      if (p['SPDXID'] == null) {
        errors.add(tr('packages[{i}] : SPDXID manquant', {'i': i}));
      }
      if (p['name'] == null) {
        errors.add(
            tr('packages[{i}] : name manquant', {'i': i}));
      }
      if (p['versionInfo'] == null && strict) {
        errors.add(tr('[strict] packages[{i}] ({name}) : versionInfo manquant', {'i': i, 'name': p['name'] ?? '?'}));
      }
    }
  }
}

void _validateSpdx3(Map<String, dynamic> json, List<String> errors,
    {bool strict = false}) {
  if (json['@context'] == null) {
    errors.add(tr('@context manquant'));
  }
  final graph = json['@graph'];
  if (graph == null) {
    errors.add(tr('@graph manquant'));
    return;
  }
  if (graph is! List) {
    errors.add(
        tr('@graph doit être un tableau JSON'));
    return;
  }
  final hasDoc = graph.any(
      (node) => node is Map && (node['type'] as String?) == 'SpdxDocument');
  if (!hasDoc) {
    errors.add(tr('@graph ne contient pas d\'élément SpdxDocument'));
  }
  for (int i = 0; i < graph.length; i++) {
    final node = graph[i] as Map?;
    if (node == null) continue;
    if (node['spdxId'] == null && strict) {
      errors.add(tr('[strict] @graph[{i}] : spdxId manquant', {'i': i}));
    }
  }
}

/// Commande qui relance ce programme (exécutable compilé, ou `dart script`).
List<String> _selfCommand() {
  final exe = Platform.resolvedExecutable;
  final script = Platform.script.toFilePath();
  return script == exe ? [exe] : [exe, script];
}

Future<void> _runWatch(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('state-dir',
        abbr: 'd',
        mandatory: true,
        help: tr('Dossier où mémoriser le dernier scan de chaque SBOM (créé si\nabsent). Le premier passage établit l\'état initial.'))
    ..addOption('scanner',
        abbr: 's',
        defaultsTo: 'grype',
        allowed: _validScanners.toList(),
        help: tr('Scanner de vulnérabilités.'))
    ..addOption('interval',
        abbr: 'i',
        help: tr('Rescanne en boucle à cet intervalle (90s, 30m, 6h, 1d).\nOmis : un seul passage (adapté à cron / CI).'))
    ..addOption('notify-cmd',
        help: tr('Commande shell lancée pour chaque SBOM ayant de nouvelles CVE.\nVariables : SBOMGEN_WATCH_SBOM, SBOMGEN_WATCH_NEW (nombre),\nSBOMGEN_WATCH_REPORT (JSON des nouveaux constats). Si elle\néchoue, l\'état n\'est pas mis à jour : nouvelle tentative au\npassage suivant.'))
    ..addMultiOption('scan-arg',
        help: tr('Option transmise telle quelle à `scan` (répétable), p. ex.\n--scan-arg=--no-enrich.'))
    ..addOption('format',
        abbr: 'f',
        allowed: ['text', 'json'],
        defaultsTo: 'text',
        help: tr('Sortie : text (défaut) ou json (un événement par ligne).'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.'));

  void usage() => stdout.writeln(tr('sbom_generator watch – Rescanne des SBOM et signale les nouvelles CVE.\n\nUsage:\n  sbom_generator watch sbom/ autre.cdx.json --state-dir .watch\n  sbom_generator watch sbom/ -d .watch --interval 6h --notify-cmd \'./alerte.sh\'\n\nChaque SBOM est scanné (`scan --format json`) puis comparé au scan précédent.\nUn dossier est parcouru récursivement (*.cdx.json, *.spdx.json, *.spdx3.jsonld).\n\n{usage}\n\nCodes de retour (un seul passage) :\n  0  Aucune nouvelle CVE\n  1  Erreur (usage, SBOM illisible, scan ou notification en échec)\n  3  Au moins une nouvelle CVE\n', {'usage': parser.usage}));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('watch: ${_argError(e.message)}');
    usage();
    exit(1);
  }
  if (!(args['help'] as bool)) _requireMandatory(parser, args, 'watch', usage);
  if (args['help'] as bool) {
    usage();
    exit(0);
  }
  if (args.rest.isEmpty) {
    stderr.writeln(tr('watch: au moins un SBOM ou dossier requis.'));
    usage();
    exit(1);
  }
  Duration? interval;
  final intervalText = args['interval'] as String?;
  if (intervalText != null) {
    try {
      interval = parseWatchInterval(intervalText);
    } on FormatException catch (e) {
      stderr.writeln('watch: --interval : ${e.message}');
      exit(1);
    }
  }

  final stateDir = args['state-dir'] as String;
  final asJson = args['format'] == 'json';
  final notifyCmd = args['notify-cmd'] as String?;
  Directory(stateDir).createSync(recursive: true);

  void emit(Map<String, dynamic> event, String text) =>
      print(asJson ? jsonEncode(event) : text);

  /// Un passage sur tous les SBOM : (SBOM avec nouvelles CVE, erreurs).
  Future<(int, int)> pass() async {
    var withNew = 0, errors = 0;
    final sboms = collectWatchedSboms(args.rest);
    if (sboms.isEmpty) {
      emit({'event': 'watch', 'status': 'error', 'error': 'no sbom'},
          tr('watch: aucun SBOM trouvé.'));
      return (0, 1);
    }
    for (final sbom in sboms) {
      void fail(String why) {
        errors++;
        emit({'event': 'watch', 'sbom': sbom, 'status': 'error', 'error': why},
            '$sbom : ${tr('erreur')} — $why');
      }

      if (!File(sbom).existsSync()) {
        fail(tr('fichier introuvable'));
        continue;
      }
      final cmd = _selfCommand();
      final scan = await Process.run(cmd.first, [
        ...cmd.skip(1),
        'scan',
        '--sbom',
        sbom,
        '--scanner',
        args['scanner'] as String,
        '--format',
        'json',
        ...(args['scan-arg'] as List<String>),
      ]);
      Map<String, dynamic> current;
      try {
        current = jsonDecode('${scan.stdout}') as Map<String, dynamic>;
        if (current['findings'] is! List) throw const FormatException('');
      } on FormatException {
        final err = '${scan.stderr}'.trim().split('\n').last;
        fail(tr('scan impossible (code {exitCode}) {err}', {'exitCode': scan.exitCode, 'err': err}));
        continue;
      }

      final stateFile = watchStateFile(stateDir, sbom);
      Map<String, dynamic>? previous;
      if (File(stateFile).existsSync()) {
        try {
          previous = jsonDecode(File(stateFile).readAsStringSync())
              as Map<String, dynamic>;
        } on FormatException {
          previous = null; // état corrompu : on repart d'un état initial
        }
      }

      if (previous == null) {
        File(stateFile).writeAsStringSync(jsonEncode(current));
        final total = (current['findings'] as List).length;
        emit({
          'event': 'watch',
          'sbom': sbom,
          'status': 'initial',
          'total': total
        }, '$sbom : ${tr('état initial enregistré')} ($total CVE)');
        continue;
      }

      final diff = diffScans(previous, current);
      if (diff.added.isEmpty) {
        File(stateFile).writeAsStringSync(jsonEncode(current));
        emit(
            {
              'event': 'watch',
              'sbom': sbom,
              'status': 'unchanged',
              'total': diff.total,
              'resolved': diff.resolved,
            },
            '$sbom : ${tr('aucune nouvelle CVE')} (${diff.total} CVE'
            '${diff.resolved > 0 ? ', ${tr('{resolved} corrigée(s)', {'resolved': diff.resolved})}' : ''})');
        continue;
      }

      withNew++;
      emit(
          {
            'event': 'watch',
            'sbom': sbom,
            'status': 'changed',
            'total': diff.total,
            'resolved': diff.resolved,
            'new': diff.added,
          },
          [
            '$sbom : ${diff.added.length} ${tr('nouvelle(s) CVE')} (${diff.total} CVE)',
            for (final f in diff.added)
              '  + ${f['id']}  ${f['package']}  ${f['severity'] ?? ''}',
          ].join('\n'));

      var notified = true;
      if (notifyCmd != null) {
        final report = File('$stateFile.new.json')
          ..writeAsStringSync(jsonEncode(diff.added));
        final r = await Process.run('sh', [
          '-c',
          notifyCmd
        ], environment: {
          'SBOMGEN_WATCH_SBOM': sbom,
          'SBOMGEN_WATCH_NEW': '${diff.added.length}',
          'SBOMGEN_WATCH_REPORT': report.path,
        });
        if (r.exitCode != 0) {
          notified = false;
          fail(tr('--notify-cmd en échec (code {exitCode}) : état conservé', {'exitCode': r.exitCode}));
        }
      }
      if (notified) File(stateFile).writeAsStringSync(jsonEncode(current));
    }
    return (withNew, errors);
  }

  if (interval == null) {
    final (withNew, errors) = await pass();
    exit(errors > 0 ? 1 : (withNew > 0 ? 3 : 0));
  }
  while (true) {
    await pass();
    await Future<void>.delayed(interval);
  }
}

Future<void> _runVerify(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('bundle',
        abbr: 'b',
        help: tr('Bundle de signature (défaut : <sbom>.bundle, écrit par --sign).'))
    ..addOption('key',
        abbr: 'k',
        help: tr('Clé publique cosign (vérification à clé).'))
    ..addOption('certificate-identity',
        help: tr('Identité attendue du certificat (sans clé).'))
    ..addOption('certificate-identity-regexp',
        help: tr('Identité du certificat, en expression régulière.'))
    ..addOption('certificate-oidc-issuer',
        help: tr('Émetteur OIDC attendu du certificat (sans clé).'))
    ..addOption('certificate-oidc-issuer-regexp',
        help: tr('Émetteur OIDC du certificat, en expression régulière.'))
    ..addOption('format',
        abbr: 'f',
        allowed: ['text', 'json'],
        defaultsTo: 'text',
        help: tr('Format du rapport : text (défaut) ou json (stdout).'))
    ..addFlag('help', abbr: 'h', negatable: false, help: tr('Aide.'));

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('verify: ${_argError(e.message)}');
    _printVerifyUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) {
    _printVerifyUsage(parser);
    exit(0);
  }
  if (args.rest.length != 1) {
    stderr.writeln(tr('verify: exactement un fichier SBOM requis.'));
    _printVerifyUsage(parser);
    exit(1);
  }

  final key = args['key'] as String?;
  final identity = args['certificate-identity'] as String?;
  final identityRe = args['certificate-identity-regexp'] as String?;
  final issuer = args['certificate-oidc-issuer'] as String?;
  final issuerRe = args['certificate-oidc-issuer-regexp'] as String?;
  // Sans clé, cosign exige l'identité ET l'émetteur : on le dit avant de
  // lancer l'outil plutôt que de relayer son message.
  if (key == null &&
      ((identity ?? identityRe) == null || (issuer ?? issuerRe) == null)) {
    stderr.writeln(tr('verify: --key, ou --certificate-identity[-regexp] et --certificate-oidc-issuer[-regexp], requis.'));
    exit(1);
  }

  final path = args.rest.single;
  final result = await verifySbomSignature(
    sbomPath: path,
    bundlePath: args['bundle'] as String?,
    key: key,
    identity: identity,
    identityRegexp: identityRe,
    issuer: issuer,
    issuerRegexp: issuerRe,
  );

  final label = switch (result.status) {
    SignatureStatus.verified => tr('signature valide'),
    SignatureStatus.invalid => tr('signature INVALIDE'),
    SignatureStatus.fileMissing =>
      tr('SBOM ou bundle introuvable'),
    SignatureStatus.cosignMissing =>
      tr('cosign introuvable'),
  };
  if (args['format'] == 'json') {
    print(const JsonEncoder.withIndent('  ').convert({
      'path': path,
      'status': result.status.name,
      'verified': result.verified,
      if (result.detail.isNotEmpty) 'detail': result.detail,
    }));
  } else {
    print('$path : $label');
    if (!result.verified && result.detail.isNotEmpty) {
      stderr.writeln(result.detail);
    }
  }
  exit(switch (result.status) {
    SignatureStatus.verified => 0,
    SignatureStatus.invalid => 2,
    _ => 1,
  });
}

void _printVerifyUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator verify – Vérifie la signature cosign d\'un SBOM (cosign verify-blob).\n\nUsage:\n  sbom_generator verify sbom.cdx.json --key cosign.pub\n  sbom_generator verify sbom.cdx.json \\\n      --certificate-identity moi@exemple.org \\\n      --certificate-oidc-issuer https://accounts.google.com\n\nLe bundle est celui écrit par `--sign` (<sbom>.bundle). Requiert cosign.\n\n{usage}\n\nCodes de retour:\n  0  Signature valide\n  1  Erreur d\'usage, fichier ou cosign introuvable\n  2  Signature invalide\n', {'usage': parser.usage}));
}

void _printValidateUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator validate – Vérifie la structure d\'un ou plusieurs fichiers SBOM.\n\nUsage:\n  sbom_generator validate <fichier1.cdx.json> [fichier2.spdx.json ...]\n\nFormats supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD\n\n{usage}\n\nCodes de retour:\n  0  Tous les fichiers sont valides\n  1  Au moins un fichier est invalide ou introuvable\n', {'usage': parser.usage}));
}

void _printUsage(ArgParser parser) {
  stdout.writeln(tr('sbom_generator – Génère un SBOM à partir d\'une liste de paquets ou d\'une image de conteneur OCI.\n\nUsage:\n  dart run bin/sbom_generator.dart --input <file> [options]\n  dart run bin/sbom_generator.dart --image <ref>  [options]\n  dart run bin/sbom_generator.dart --image <ref> --input <file> [options]\n  dart run bin/sbom_generator.dart --binary <fichier> [options]\n\n{usage}\n\nFormat du fichier d\'entrée (--input) :\n  Une référence de paquet par ligne. Les lignes commençant par # sont ignorées.\n  Les références peuvent être mélangées :\n    • RPM : nom de paquet installé/NEVRA, ou chemin vers un fichier .rpm\n    • Wheel Python : chemin vers un fichier .whl\n    • Archive source : chemin vers un .tar, .tar.gz ou .tgz\n        - sdist Python (PKG-INFO présent) → PURL pkg:pypi/…\n        - Archive générique (sans métadonnées) → PURL pkg:generic/…\n    • Debian : chemin vers un fichier .deb\n    • requirements.txt : chemin vers un fichier de dépendances pip\n    • Manifestes/lockfiles : go.sum, go.mod, package-lock.json, yarn.lock,\n      pnpm-lock.yaml, Cargo.lock, composer.lock, Gemfile.lock,\n      pom.xml, pubspec.lock, pubspec.yaml\n\nFormats d\'image OCI (--image) :\n    • Registre  : nginx:latest  ubuntu:22.04  myregistry.io/app@sha256:…\n    • Archive   : /chemin/image.tar        (docker save / skopeo docker-archive)\n    • OCI layout: /chemin/vers/oci_dir/    (dossier contenant index.json)\n\nExamples:\n  # CycloneDX depuis une image Docker Hub (via syft, défaut)\n  dart run bin/sbom_generator.dart --image nginx:latest -o nginx.cdx.json\n\n  # SPDX 2.3 depuis une archive tar, backend trivy\n  dart run bin/sbom_generator.dart --image ./ubuntu.tar --oci-tool trivy -f spdx -o sbom.spdx.json\n\n  # OCI layout directory, backend skopeo\n  dart run bin/sbom_generator.dart --image ./oci_layout/ --oci-tool skopeo -o sbom.cdx.json\n\n  # CycloneDX depuis une image Docker Hub, backend cdxgen\n  dart run bin/sbom_generator.dart --image nginx:latest --oci-tool cdxgen -o nginx.cdx.json\n\n  # Un SBOM par couche de l\'image (delta), en plus du global\n  dart run bin/sbom_generator.dart --image ./app.tar --per-layer -o out/app\n  dart run bin/sbom_generator.dart --image ./app.tar --per-layer --layer-mode rootfs -o out/app\n\n  # Combiner image OCI + liste de paquets supplémentaires\n  dart run bin/sbom_generator.dart --image nginx:latest -i extra_pkgs.txt -o sbom.cdx.json\n\n  # Multi-format en un seul passage\n  dart run bin/sbom_generator.dart --image nginx:latest -f cyclonedx,spdx,markdown -o sbom\n\n  # Depuis un fichier de paquets (mode classique)\n  dart run bin/sbom_generator.dart -i packages.txt -o sbom.cdx.json\n\n  # Binaire lié statiquement (ex. exécutable Go) — dépendances embarquées\n  # lues via syft (buildinfo Go / classifieur générique), sans dépôt/registre\n  dart run bin/sbom_generator.dart --binary /usr/local/bin/mon-app -o app.cdx.json\n', {'usage': parser.usage}));
}
