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
import 'package:sbom_generator/license_report_generator.dart';

const _version = '1.3.0';

const _validFormats = {'cyclonedx', 'spdx', 'spdx3', 'json', 'markdown', 'asciidoc', 'html', 'csv'};
const _validScanners = {'grype', 'osv', 'trivy', 'all'};
const _validOciTools = {'syft', 'trivy', 'skopeo'};
const _validDateFields = {'published', 'modified', 'latest'};
const _validScanFormats = {'text', 'sarif'};
const _validCycloneDxVersions = CycloneDxGenerator.supportedSpecVersions;
const _validTlpClassifications = CycloneDxGenerator.validTlpClassifications;

Future<void> main(List<String> arguments) async {
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

  final parser = ArgParser()
    ..addOption(
      'input',
      abbr: 'i',
      help: 'Input file containing one package reference per line, a single\n'
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
    )
    ..addOption(
      'image',
      abbr: 'I',
      help: 'OCI container image to analyse.\n'
          'Accepted formats :\n'
          '  • Registre  : nginx:latest  ubuntu@sha256:…\n'
          '  • Archive   : /path/image.tar  (docker save)\n'
          '  • OCI layout: /path/to/oci_dir/  (index.json present)\n'
          'Combine with --oci-tool pour choisir le backend.',
    )
    ..addOption(
      'oci-tool',
      defaultsTo: 'syft',
      help: 'Backend d\'analyse OCI (utilisé avec --image).\n'
          '  syft    Anchore Syft (défaut) — tous types de paquets\n'
          '  trivy   Aqua Trivy — tous types de paquets\n'
          '  skopeo  Skopeo + extraction manuelle (dpkg/rpm/apk)',
    )
    ..addOption(
      'output',
      abbr: 'o',
      defaultsTo: 'sbom.json',
      help: 'Output file path.\n'
          'Single format : used as-is.\n'
          'Multiple formats (-f a,b) : used as a base path; format-specific\n'
          'extensions are appended (.cdx.json, .spdx.json, .spdx3.jsonld, …).',
    )
    ..addOption(
      'format',
      abbr: 'f',
      defaultsTo: 'cyclonedx',
      help: 'Output format(s), comma-separated.\n'
          '  cyclonedx  CycloneDX 1.6 or 1.7 JSON (default: 1.6, see --cyclonedx-version)\n'
          '  spdx       SPDX 2.3 JSON\n'
          '  spdx3      SPDX 3.0 JSON-LD\n'
          '  json       Custom human-friendly JSON\n'
          '  markdown   Tableau Markdown des licences\n'
          '  asciidoc   Tableau AsciiDoc des licences\n'
          '  html       Rapport HTML interactif (tableau filtrable)\n'
          '  csv        Fichier CSV (une ligne par paquet)\n'
          'Example: -f cyclonedx,spdx,csv',
    )
    ..addOption(
      'name',
      abbr: 'n',
      help: 'Name for the SBOM document / root component.',
    )
    ..addOption(
      'rpm-dir',
      abbr: 'd',
      help: 'Directory to search recursively for .rpm files.\n'
          'Used to resolve bare package names (no path, no extension)\n'
          'to local .rpm files instead of querying the installed database.',
    )
    ..addFlag(
      'verbose',
      abbr: 'v',
      defaultsTo: false,
      negatable: false,
      help: 'Print progress details.',
    )
    ..addOption(
      'concurrency',
      abbr: 'c',
      defaultsTo: '4',
      help: 'Maximum packages processed concurrently.\n'
          '1 = sequential. 0 = unlimited.',
    )
    ..addOption(
      'license-map',
      abbr: 'l',
      help: 'Path to a license override file.\n'
          'Format: one "package_name: SPDX-expression" per line.\n'
          'Lines starting with # are ignored.\n'
          'Overrides the detected license for matching package names.',
    )
    ..addMultiOption(
      'deny-license',
      help: 'Fait échouer la génération si un paquet a cette licence.\n'
          'Peut être répété. Supporte les expressions SPDX partielles.\n'
          'Exemple : --deny-license GPL-3.0 --deny-license AGPL-3.0',
    )
    ..addOption(
      'cyclonedx-version',
      defaultsTo: '1.6',
      allowed: _validCycloneDxVersions,
      help: 'Version de la spécification CycloneDX à générer.\n'
          '  1.6  (défaut, la plus répandue chez les consommateurs actuels)\n'
          '  1.7  Ajoute citations/patentAssertions/distributionConstraints '
          'quand --tlp ou --patent-map sont fournis.',
    )
    ..addOption(
      'tlp',
      allowed: _validTlpClassifications,
      help: 'Classification TLP (Traffic Light Protocol) du BOM.\n'
          'Nécessite --cyclonedx-version 1.7.\n'
          'Valeurs : ${_validTlpClassifications.join(", ")}',
    )
    ..addOption(
      'patent-map',
      help: 'Chemin vers un fichier de déclarations de brevets.\n'
          'Nécessite --cyclonedx-version 1.7.\n'
          'Format : une ligne "package_name: numéro|juridiction|statut|type"\n'
          'Exemple : openssl: US1234567|US|granted|license',
    )
    ..addOption(
      'min-quality-score',
      help: 'Score sbomqs minimum (0-10). Échoue si le score est inférieur.\n'
          'Requiert que sbomqs soit installé.',
    )
    ..addFlag(
      'sign',
      defaultsTo: false,
      negatable: false,
      help: 'Signe le SBOM généré avec cosign (requiert cosign installé).\n'
          'La clé est lue depuis les variables d\'environnement cosign standard.',
    )
    ..addFlag(
      'version',
      defaultsTo: false,
      negatable: false,
      help: 'Print version and exit.',
    )
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: 'Show this help message.',
    );

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    _err('Argument error: ${e.message}');
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

  if (!args.wasParsed('input') && !args.wasParsed('image')) {
    _err('Au moins une source est requise : --input ou --image.');
    _printUsage(parser);
    exit(1);
  }

  final inputPath = args['input'] as String?;
  final imageRef = args['image'] as String?;
  final ociTool = args['oci-tool'] as String;
  final outputPath = args['output'] as String;
  final docName = args['name'] as String?;
  final verbose = args['verbose'] as bool;
  final rpmDir = args['rpm-dir'] as String?;
  final concurrencyN = () {
    final n = int.tryParse(args['concurrency'] as String) ?? 4;
    if (n < 0) {
      _err('--concurrency must be ≥ 0.');
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
    _err('--format must not be empty.');
    exit(1);
  }
  for (final f in formats) {
    if (!_validFormats.contains(f)) {
      _err('Unknown format "$f". Valid: ${_validFormats.join(', ')}');
      exit(1);
    }
  }

  // Validation --oci-tool
  if (!_validOciTools.contains(ociTool)) {
    _err('Outil OCI inconnu "$ociTool". Valides : ${_validOciTools.join(', ')}');
    exit(1);
  }

  // Load license overrides
  final licenseMapPath = args['license-map'] as String?;
  final licenseOverrides =
      licenseMapPath != null ? _parseLicenseMap(licenseMapPath) : <String, String>{};
  final denyLicenses = args['deny-license'] as List<String>;
  final minQualityScore = args['min-quality-score'] as String?;
  final signSbom = args['sign'] as bool;
  if (verbose && licenseOverrides.isNotEmpty) {
    print('License overrides: ${licenseOverrides.length} entr(ée(s)) chargée(s).');
  }

  // CycloneDX 1.7 : version cible + champs optionnels associés
  final cycloneDxVersion = args['cyclonedx-version'] as String;
  final tlp = args['tlp'] as String?;
  final patentMapPath = args['patent-map'] as String?;
  final patentMap =
      patentMapPath != null ? _parsePatentMap(patentMapPath) : <String, PatentAssertion>{};
  if (cycloneDxVersion != '1.7' && (tlp != null || patentMap.isNotEmpty)) {
    _err('--tlp et --patent-map nécessitent --cyclonedx-version 1.7.');
    exit(1);
  }
  // Le BOM ne peut réellement attribuer les données de composants à un outil
  // externe que lorsque celui-ci a effectivement produit la liste (--image).
  final citationSource =
      (cycloneDxVersion == '1.7' && imageRef != null) ? ociTool : null;

  if (inputPath != null) {
    final inputType = await FileSystemEntity.type(inputPath);
    if (inputType == FileSystemEntityType.notFound) {
      _err('Input not found: $inputPath');
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
        print('${found.length} fichier(s) de paquet trouvé(s) dans $inputPath.');
      }
      if (packageRefs.isEmpty && imageRef == null) {
        _err('Aucun paquet reconnu dans le dossier $inputPath.');
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
        _err('$inputPath ne semble pas être un fichier texte lisible. '
            'Si c\'est une archive (.zip/.tar/.tar.gz/.tgz/.whl/.deb/.rpm/.jar), '
            'passez-la directement via --input, sinon --input doit être un '
            'fichier listant une référence de paquet par ligne, ou un dossier '
            'à scanner.');
        exit(1);
      }
      packageRefs = lines
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty && !l.startsWith('#'))
          .toList();

      if (packageRefs.isEmpty && imageRef == null) {
        _err('No packages found in $inputPath '
            '(empty file or all lines are comments).');
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
      _err('RPM directory not found: $rpmDir');
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
      print('Found ${rpmExactIndex.length} RPM file(s) in $rpmDir.');
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
      preloadedPackages.addAll(pubspecParser.parsePubspecLock(ref));
    } else if (_isPubspecYaml(ref)) {
      preloadedPackages.addAll(pubspecParser.parsePubspecYaml(ref));
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
      _err('$ociTool introuvable ou non fonctionnel — requis pour --image.');
      exit(1);
    }
    if (verbose) {
      print('$ociTool : ${(ociCheck.stdout as String).split('\n').first.trim()}');
    }

    final refType = OciParser.detectRefType(imageRef);
    final refTypeLabel = switch (refType) {
      OciRefType.registry => 'registre',
      OciRefType.tar => 'archive tar',
      OciRefType.ociLayout => 'OCI layout',
    };
    print('Analyse de l\'image OCI ($refTypeLabel) via $ociTool : $imageRef…');

    try {
      final ociResult =
          await OciParser().parseImage(imageRef, ociTool, verbose: verbose);
      ociPackages.addAll(ociResult.packages);
      ociOs = ociResult.os;
      print('${ociPackages.length} paquet(s) trouvé(s) dans l\'image.');
      if (verbose && ociOs != null) {
        print('OS de base détecté : ${ociOs.id} ${ociOs.version}');
      }
    } catch (e) {
      _err('Échec de l\'analyse OCI : $e');
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
      _err('rpm binary not found or not functional.');
      exit(1);
    }
    if (verbose) print('rpm: ${(rpmCheck.stdout as String).trim()}');
  }

  if (hasWhl || hasTar || hasZip) {
    final py3Check = await Process.run('python3', ['--version']);
    if (py3Check.exitCode != 0) {
      _err('python3 not found — required to read .whl, tar, and zip archives.');
      exit(1);
    }
    if (verbose) print('python3: ${(py3Check.stdout as String).trim()}');
  }

  if (hasDeb) {
    final debCheck = await Process.run('dpkg-deb', ['--version']);
    if (debCheck.exitCode != 0) {
      _err('dpkg-deb not found — required to read .deb files.');
      exit(1);
    }
    if (verbose)
      print(
          'dpkg-deb: ${(debCheck.stdout as String).split('\n').first.trim()}');
  }

  if (hasJar) {
    final unzipCheck = await Process.run('unzip', ['-v']);
    if (unzipCheck.exitCode != 0) {
      _err('unzip not found — required to read .jar files.');
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
  final conLabel = concurrencyN == 0 ? 'illimité' : '$concurrencyN';
  if (mainRefs.isNotEmpty) {
    print('Querying ${mainRefs.length} package(s) — concurrence : $conLabel'
        '${preloadedPackages.isNotEmpty ? " (+ ${preloadedPackages.length} depuis requirements)" : ""}…');
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
                stderr.writeln(
                  'Warning: multiple RPM files match "$ref"; '
                  'using ${paths.first.split('/').last}',
                );
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
      final n = uniquePackages.where((p) => licenseOverrides.containsKey(p.name)).length;
      print('License overrides applied to $n package(s).');
    }
  }

  final failedNote = failed > 0 ? '  ($failed échec(s))' : '';
  final dupeNote = dupes > 0 ? '  ($dupes doublon(s) supprimé(s))' : '';
  print(
      'Analysés : ${uniquePackages.length}/$total paquet(s).$failedNote$dupeNote');

  // --- Error report ---
  if (failedRefs.isNotEmpty) {
    stderr.writeln('');
    stderr.writeln('⚠  ${failedRefs.length} paquet(s) ignoré(s) :');
    for (final r in failedRefs) {
      final name = r.contains('/') ? r.split('/').last : r;
      stderr.writeln('   • $name');
    }
    stderr.writeln('');
  }

  if (uniquePackages.isEmpty) {
    _err('No packages could be parsed. Aborting.');
    exit(1);
  }

  // --- Build dependency graph (skipped when all formats are markdown) ---
  final dependencies = <PackageDependency>[];
  if (formats.any((f) => f != 'markdown' && f != 'asciidoc' && f != 'html')) {
    print('Resolving dependencies…');
    dependencies.addAll(rpmParser.buildDependencies(uniquePackages));
    final relCount =
        dependencies.fold<int>(0, (sum, d) => sum + d.dependsOn.length);
    print('Found $relCount intra-list dependency relationship(s).');

    if (verbose) {
      for (final dep in dependencies.where((d) => d.dependsOn.isNotEmpty)) {
        final srcName = uniquePackages
            .firstWhere((p) => p.bomRef == dep.sourceRef,
                orElse: () => uniquePackages.first)
            .name;
        print('  $srcName → ${dep.dependsOn.length} dep(s)');
      }
    }
  }

  // --- Generate SBOM (loop over requested formats) ---
  final outputBase = formats.length > 1 ? _basePath(outputPath) : null;
  for (final fmt in formats) {
    final outPath =
        outputBase != null ? '$outputBase${_formatExtension(fmt)}' : outputPath;
    print('Generating SBOM ($fmt)…');
    try {
      switch (fmt) {
        case 'cyclonedx':
          await CycloneDxGenerator().writeToFile(
              uniquePackages, dependencies, outPath,
              documentName: docName,
              specVersion: cycloneDxVersion,
              tlp: tlp,
              citationSource: citationSource,
              patentsByPackageName: patentMap,
              osInfo: ociOs);
        case 'spdx':
          await SpdxGenerator().writeToFile(
              uniquePackages, dependencies, outPath,
              documentName: docName, osInfo: ociOs);
        case 'spdx3':
          await Spdx3Generator().writeToFile(
              uniquePackages, dependencies, outPath,
              documentName: docName, osInfo: ociOs);
        case 'json':
          await SimpleJsonGenerator().writeToFile(
              uniquePackages, dependencies, outPath, documentName: docName);
        case 'markdown':
          await MarkdownGenerator()
              .writeToFile(uniquePackages, outPath, documentName: docName);
        case 'asciidoc':
          await AsciidocGenerator()
              .writeToFile(uniquePackages, outPath, documentName: docName);
        case 'html':
          await HtmlGenerator()
              .writeToFile(uniquePackages, outPath, documentName: docName);
        case 'csv':
          await CsvGenerator()
              .writeToFile(uniquePackages, outPath, documentName: docName);
      }
    } catch (e, st) {
      _err('Failed to write SBOM ($fmt): $e');
      if (verbose) stderr.writeln(st);
      exit(1);
    }
    final sz = await File(outPath).length();
    print('SBOM written → $outPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
  }

  // ── Vérification des politiques ──────────────────────────────────────────
  final checker = PolicyChecker();
  int policyFailures = 0;

  if (denyLicenses.isNotEmpty) {
    final violations = checker.checkDenyLicenses(uniquePackages, denyLicenses);
    if (violations.isNotEmpty) {
      stderr.writeln('\nPolitique licence : ${violations.length} violation(s) :');
      for (final v in violations) {
        stderr.writeln('  [DENY] ${v.packageName} ${v.version} — ${v.license}');
      }
      policyFailures += violations.length;
    } else if (verbose) {
      print('Politiques licences : OK');
    }
  }

  if (minQualityScore != null) {
    final threshold = double.tryParse(minQualityScore);
    if (threshold == null) {
      stderr.writeln('--min-quality-score : valeur invalide "$minQualityScore"');
      exit(1);
    }
    final primaryOut = formats.length == 1
        ? outputPath
        : '${_basePath(outputPath)}${_formatExtension(formats.first)}';
    final score = await checker.runSbomqs(primaryOut, verbose: verbose);
    if (score != null) {
      if (score < threshold) {
        stderr.writeln(
            '\nPolitique qualité : score=$score < seuil=$threshold → ÉCHEC');
        policyFailures++;
      } else if (verbose) {
        print('Politique qualité : score=$score >= seuil=$threshold → OK');
      }
    }
  }

  // ── Signature cosign ─────────────────────────────────────────────────────
  if (signSbom) {
    final primaryOut = formats.length == 1
        ? outputPath
        : '${_basePath(outputPath)}${_formatExtension(formats.first)}';
    await _signWithCosign(primaryOut, verbose: verbose);
  }

  if (policyFailures > 0) {
    stderr.writeln('\n$policyFailures politique(s) violée(s) — code retour 2');
    exit(2);
  }
}

// ── Sous-commande diff ────────────────────────────────────────────────────────

Future<void> _runDiff(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('output', abbr: 'o',
        help: 'Fichier de sortie (JSON). Défaut : affichage console.')
    ..addFlag('json', defaultsTo: false, negatable: false,
        help: 'Sortie au format JSON structuré.')
    ..addFlag('no-color', defaultsTo: false, negatable: false,
        help: 'Désactive la coloration ANSI.')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('diff: ${e.message}');
    _printDiffUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) { _printDiffUsage(parser); exit(0); }

  final rest = args.rest;
  if (rest.length != 2) {
    stderr.writeln('diff: deux fichiers SBOM requis.');
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
    final jsonStr = const JsonEncoder.withIndent('  ').convert(differ.toJson(result));
    final outPath = args['output'] as String?;
    if (outPath != null) {
      await File(outPath).writeAsString(jsonStr);
      print('Diff écrit → $outPath');
    } else {
      print(jsonStr);
    }
  } else {
    differ.printDiff(result, color: !(args['no-color'] as bool));
  }

  exit(result.isEmpty ? 0 : 1);
}

void _printDiffUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator diff – Compare deux fichiers SBOM et affiche les changements.

Usage:
  sbom_generator diff <avant.cdx.json> <après.cdx.json> [options]

${parser.usage}

Codes de retour:
  0  Aucun changement
  1  Des changements ont été détectés
''');
}

// ── Sous-commande merge ───────────────────────────────────────────────────────

Future<void> _runMerge(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('output', abbr: 'o', mandatory: true,
        help: 'Fichier SBOM fusionné de sortie (même format que le premier '
            'fichier d\'entrée : .cdx.json ou .spdx.json).')
    ..addOption('name', abbr: 'n', help: 'Nom du document SBOM fusionné.')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('merge: ${e.message}');
    _printMergeUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) { _printMergeUsage(parser); exit(0); }

  final files = args.rest;
  if (files.length < 2) {
    stderr.writeln('merge: au moins deux fichiers SBOM requis.');
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
  await File(outPath).writeAsString(
      const JsonEncoder.withIndent('  ').convert(merged));
  final total = (merged['components'] as List? ?? merged['packages'] as List? ?? [])
      .length;
  print('Fusion de ${files.length} SBOMs → $total composant(s) → $outPath');
}

void _printMergeUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator merge – Fusionne plusieurs fichiers SBOM en un seul.

Usage:
  sbom_generator merge <a.cdx.json> <b.cdx.json> [...] -o merged.cdx.json

${parser.usage}
''');
}

// ── Signature cosign ──────────────────────────────────────────────────────────

Future<void> _signWithCosign(String sbomPath, {bool verbose = false}) async {
  final check = await Process.run('cosign', ['version']);
  if (check.exitCode != 0) {
    stderr.writeln('sign: cosign introuvable — signature ignorée.');
    return;
  }
  if (verbose) print('cosign : signature de $sbomPath…');
  final result = await Process.run('cosign', [
    'sign-blob',
    '--yes',
    '--bundle', '$sbomPath.bundle',
    sbomPath,
  ]);
  if (result.exitCode != 0) {
    stderr.writeln('cosign: échec (code ${result.exitCode}) : ${result.stderr}');
  } else {
    print('Signature → $sbomPath.bundle');
  }
}

bool _isTar(String ref) =>
    ref.endsWith('.tar') || ref.endsWith('.tar.gz') || ref.endsWith('.tgz');

bool _isJar(String ref) => ref.endsWith('.jar');

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

/// Strips well-known SBOM extensions from [output] to produce a base path.
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

/// Parses a license override file (one "name: SPDX-expression" per line).
Map<String, String> _parseLicenseMap(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    _err('License map file not found: $path');
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

/// Parses a patent declaration file (CycloneDX 1.7 `patentAssertions`).
/// One line per package: `package_name: patentNumber|jurisdiction|legalStatus|assertionType`.
/// Example: `openssl: US1234567|US|granted|license`.
Map<String, PatentAssertion> _parsePatentMap(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    _err('Patent map file not found: $path');
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
      _err('--patent-map : ligne invalide (attendu "name: number|jurisdiction|status|type") : "$trimmed"');
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
        mandatory: true,
        help: 'Chemin vers le fichier SBOM à analyser (.cdx.json, .spdx.json…)')
    ..addOption('scanner',
        abbr: 'S',
        defaultsTo: 'grype',
        help: 'Scanner(s) à utiliser.\n'
            '  grype   Anchore Grype\n'
            '  osv     Google OSV-Scanner\n'
            '  trivy   Aqua Security Trivy\n'
            '  all     Les trois scanners')
    ..addOption('cve-after',
        help: 'N\'afficher que les CVE publiées/modifiées après cette date (YYYY-MM-DD)')
    ..addOption('cve-before',
        help: 'N\'afficher que les CVE publiées/modifiées avant cette date (YYYY-MM-DD)')
    ..addOption('cve-date-field',
        defaultsTo: 'published',
        help: 'Champ de date à utiliser pour le filtre.\n'
            '  published   Date de publication (défaut)\n'
            '  modified    Date de dernière modification\n'
            '  latest      La plus récente des deux')
    ..addFlag('include-undated',
        defaultsTo: false,
        negatable: false,
        help: 'Inclure les CVE sans date dans les résultats filtrés')
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'text',
        help: 'Format de sortie.\n'
            '  text    Texte coloré sur stdout (défaut)\n'
            '  sarif   SARIF 2.1.0 (intégration GitHub Code Scanning)')
    ..addOption('output',
        abbr: 'o',
        help: 'Fichier de sortie pour --format sarif. Si omis, écrit sur stdout.')
    ..addFlag('help',
        abbr: 'h',
        negatable: false,
        help: 'Afficher l\'aide de la sous-commande scan');

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

  final sbomFile = args['sbom'] as String;
  final scanner = args['scanner'] as String;
  final dateField = args['cve-date-field'] as String;
  final includeUndated = args['include-undated'] as bool;
  final format = args['format'] as String;
  final outputPath = args['output'] as String?;

  if (!_validScanners.contains(scanner)) {
    stderr.writeln('scan: scanner invalide "$scanner". Valides : ${_validScanners.join(', ')}');
    exit(1);
  }
  if (!_validDateFields.contains(dateField)) {
    stderr.writeln('scan: cve-date-field invalide "$dateField". Valides : ${_validDateFields.join(', ')}');
    exit(1);
  }
  if (!_validScanFormats.contains(format)) {
    stderr.writeln('scan: format invalide "$format". Valides : ${_validScanFormats.join(', ')}');
    exit(1);
  }
  if (!await File(sbomFile).exists()) {
    stderr.writeln('scan: fichier SBOM introuvable : $sbomFile');
    exit(1);
  }

  DateTime? after, before;
  final rawAfter = args['cve-after'] as String?;
  final rawBefore = args['cve-before'] as String?;
  if (rawAfter != null) {
    after = DateTime.tryParse(rawAfter);
    if (after == null) {
      stderr.writeln('scan: format de date invalide pour --cve-after : "$rawAfter" (attendu YYYY-MM-DD)');
      exit(1);
    }
  }
  if (rawBefore != null) {
    before = DateTime.tryParse(rawBefore);
    if (before == null) {
      stderr.writeln('scan: format de date invalide pour --cve-before : "$rawBefore" (attendu YYYY-MM-DD)');
      exit(1);
    }
    // La date "avant" est inclusive en fin de journée
    before = before.add(const Duration(hours: 23, minutes: 59, seconds: 59));
  }

  final scanners = scanner == 'all'
      ? ['grype', 'osv', 'trivy']
      : [scanner];

  final quiet = format == 'sarif';
  final resultsByScanner = <String, List<Map<String, dynamic>>>{};
  int totalShown = 0;
  for (final s in scanners) {
    final vulns = await _runScanner(s, sbomFile, quiet: quiet);
    if (vulns == null) continue;

    final filtered = _filterByDate(vulns, dateField, after, before, includeUndated);
    resultsByScanner[s] = filtered;
    if (!quiet) _printScanResults(s, filtered, after, before, dateField);
    totalShown += filtered.length;
  }

  if (format == 'sarif') {
    final sarif = _buildSarifReport(resultsByScanner, sbomFile);
    final json = const JsonEncoder.withIndent('  ').convert(sarif);
    if (outputPath != null) {
      await File(outputPath).writeAsString(json);
      stderr.writeln('SARIF écrit → $outputPath');
    } else {
      print(json);
    }
  }

  exit(totalShown > 0 ? 1 : 0);
}

// Retourne la liste brute [{id, severity, package, published, modified}] ou null si erreur.
Future<List<Map<String, dynamic>>?> _runScanner(
    String scanner, String sbomFile, {bool quiet = false}) async {
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
  if (!quiet) stdout.writeln('\n── Grype ──────────────────────────────────────────');
  final ProcessResult result;
  try {
    result = await Process.run('grype', [sbomFile, '--output', 'json']);
  } on ProcessException catch (e) {
    stderr.writeln('grype: introuvable (${e.message}). Installez-le ou omettez --scanner grype.');
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln('grype: erreur (code ${result.exitCode}): ${result.stderr}');
    return null;
  }
  try {
    final data = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final matches = data['matches'] as List? ?? [];
    return matches.map<Map<String, dynamic>>((m) {
      final vuln = m['vulnerability'] as Map<String, dynamic>? ?? {};
      final artifact = m['artifact'] as Map<String, dynamic>? ?? {};
      return {
        'id': vuln['id'] ?? '',
        'severity': vuln['severity'] ?? 'Unknown',
        'package': '${artifact['name'] ?? ''}@${artifact['version'] ?? ''}',
        'published': vuln['publishedDate'],
        'modified': vuln['lastModifiedDate'],
      };
    }).toList();
  } catch (e) {
    stderr.writeln('grype: impossible de parser le JSON: $e');
    return null;
  }
}

Future<List<Map<String, dynamic>>?> _runOsv(String sbomFile,
    {bool quiet = false}) async {
  if (!quiet) stdout.writeln('\n── OSV-Scanner ─────────────────────────────────────');
  final ProcessResult result;
  try {
    result = await Process.run('osv-scanner', ['--format', 'json', '--sbom', sbomFile]);
  } on ProcessException catch (e) {
    stderr.writeln('osv-scanner: introuvable (${e.message}). Installez-le ou omettez --scanner osv.');
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln('osv-scanner: erreur (code ${result.exitCode}): ${result.stderr}');
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
          final cve = aliases.firstWhere((a) => a.startsWith('CVE-'), orElse: () => '');
          final dbSev = (v['database_specific'] as Map?)?['severity'] as String? ?? '';
          out.add({
            'id': cve.isNotEmpty ? cve : v['id'] ?? '',
            'severity': dbSev.isNotEmpty ? dbSev : 'Unknown',
            'package': '$name@$version',
            'published': v['published'],
            'modified': v['modified'],
          });
        }
      }
    }
    return out;
  } catch (e) {
    stderr.writeln('osv-scanner: impossible de parser le JSON: $e');
    return null;
  }
}

Future<List<Map<String, dynamic>>?> _runTrivy(String sbomFile,
    {bool quiet = false}) async {
  if (!quiet) stdout.writeln('\n── Trivy ───────────────────────────────────────────');
  final ProcessResult result;
  try {
    result = await Process.run('trivy', ['sbom', '--format', 'json', '--quiet', sbomFile]);
  } on ProcessException catch (e) {
    stderr.writeln('trivy: introuvable (${e.message}). Installez-le ou omettez --scanner trivy.');
    return null;
  }
  if (result.exitCode > 1) {
    stderr.writeln('trivy: erreur (code ${result.exitCode}): ${result.stderr}');
    return null;
  }
  try {
    final data = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final out = <Map<String, dynamic>>[];
    for (final res in (data['Results'] as List? ?? [])) {
      for (final v in (res['Vulnerabilities'] as List? ?? [])) {
        out.add({
          'id': v['VulnerabilityID'] ?? '',
          'severity': v['Severity'] ?? 'Unknown',
          'package': '${v['PkgName'] ?? ''}@${v['InstalledVersion'] ?? ''}',
          'published': v['PublishedDate'],
          'modified': v['LastModifiedDate'],
        });
      }
    }
    return out;
  } catch (e) {
    stderr.writeln('trivy: impossible de parser le JSON: $e');
    return null;
  }
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
) {
  final sevOrder = {'Critical': 0, 'CRITICAL': 0, 'High': 1, 'HIGH': 1,
      'Medium': 2, 'MEDIUM': 2, 'Low': 3, 'LOW': 3, 'Unknown': 4, 'UNKNOWN': 4};
  vulns.sort((a, b) =>
      (sevOrder[a['severity']] ?? 5).compareTo(sevOrder[b['severity']] ?? 5));

  final filterDesc = StringBuffer();
  if (after != null || before != null) {
    filterDesc.write('  Filtre : champ=$field');
    if (after != null) filterDesc.write('  après=${_formatDate(after)}');
    if (before != null) filterDesc.write('  avant=${_formatDate(before)}');
  }
  stdout.writeln('  ${vulns.length} CVE(s) trouvée(s)$filterDesc');

  if (vulns.isEmpty) return;

  const w0 = 12, w1 = 20, w2 = 36;
  stdout.writeln(
      '${'SÉVÉRITÉ'.padRight(w0)}  ${'CVE / ID'.padRight(w1)}  PAQUET');
  stdout.writeln('${'-' * w0}  ${'-' * w1}  ${'-' * w2}');
  for (final v in vulns) {
    final sev = (v['severity'] as String).padRight(w0);
    final id = (v['id'] as String).padRight(w1);
    final pkg = v['package'] as String;
    stdout.writeln('$sev  $id  $pkg');
  }
}

String _formatDate(DateTime d) =>
    '${d.year.toString().padLeft(4, '0')}-'
    '${d.month.toString().padLeft(2, '0')}-'
    '${d.day.toString().padLeft(2, '0')}';

void _printScanUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator scan – Analyser les CVE d'un fichier SBOM avec filtre par date.

Usage:
  sbom-generator scan --sbom <fichier.cdx.json> [options]

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

Codes de retour:
  0  Aucune CVE dans la plage demandée
  1  Au moins une CVE trouvée (ou erreur de scanner)
''');
}

/// Convertit les résultats de scan (par scanner) en rapport SARIF 2.1.0,
/// consommable par exemple par `github/codeql-action/upload-sarif`.
Map<String, dynamic> _buildSarifReport(
  Map<String, List<Map<String, dynamic>>> resultsByScanner,
  String sbomFile,
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

      rulesById.putIfAbsent(id, () => {
            'id': id,
            'shortDescription': {'text': '$id — sévérité $severity'},
            'helpUri': 'https://osv.dev/vulnerability/$id',
            'properties': {'security-severity': _sarifSecurityScore(severity)},
          });

      results.add({
        'ruleId': id,
        'level': _sarifLevel(severity),
        'message': {'text': 'Paquet vulnérable : $pkg (sévérité $severity)'},
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

/// Returns a new list with license overrides applied by package name.
List<Package> _applyLicenseOverrides(
    List<Package> packages, Map<String, String> overrides) {
  if (overrides.isEmpty) return packages;
  return packages.map((pkg) {
    final lic = overrides[pkg.name];
    if (lic == null) return pkg;
    if (pkg is RpmPackage) {
      return RpmPackage(
        name: pkg.name,
        version: pkg.version,
        release: pkg.release,
        arch: pkg.arch,
        epoch: pkg.epoch,
        license: lic,
        vendor: pkg.vendor,
        url: pkg.url,
        buildTime: pkg.buildTime,
        summary: pkg.summary,
        requires: pkg.requires,
        provides: pkg.provides,
        sha256Header: pkg.sha256Header,
        sourceRpm: pkg.sourceRpm,
        sourceRef: pkg.sourceRef,
      );
    }
    if (pkg is WheelPackage) {
      return WheelPackage(
        name: pkg.name,
        version: pkg.version,
        license: lic,
        url: pkg.url,
        summary: pkg.summary,
        vendor: pkg.vendor,
        arch: pkg.arch,
        sourceRef: pkg.sourceRef,
        sha256Header: pkg.sha256Header,
        requires: pkg.requires,
        provides: pkg.provides,
        packageType: pkg.packageType,
      );
    }
    if (pkg is DebPackage) {
      return DebPackage(
        name: pkg.name,
        version: pkg.version,
        arch: pkg.arch,
        license: lic,
        vendor: pkg.vendor,
        url: pkg.url,
        summary: pkg.summary,
        sourceRef: pkg.sourceRef,
        sha256Header: pkg.sha256Header,
        requires: pkg.requires,
        provides: pkg.provides,
      );
    }
    if (pkg is OciPackage) {
      return OciPackage(
        name: pkg.name,
        version: pkg.version,
        license: lic,
        vendor: pkg.vendor,
        url: pkg.url,
        summary: pkg.summary,
        arch: pkg.arch,
        sourceRef: pkg.sourceRef,
        imageRef: pkg.imageRef,
        sha256Header: pkg.sha256Header,
        requires: pkg.requires,
        provides: pkg.provides,
        packageType: pkg.packageType,
        purlOverride: pkg.purlOverride,
      );
    }
    return pkg;
  }).toList();
}

// ── Sous-commande convert ─────────────────────────────────────────────────────

Future<void> _runConvert(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('input', abbr: 'i', mandatory: true,
        help: 'Fichier SBOM source (CycloneDX JSON ou SPDX JSON/JSON-LD).')
    ..addOption('output', abbr: 'o', mandatory: true,
        help: 'Fichier de sortie. Avec plusieurs formats (-f a,b) : chemin de base.')
    ..addOption('format', abbr: 'f', defaultsTo: 'cyclonedx',
        help: 'Format(s) cible(s), virgule-séparés.\n'
            '  cyclonedx  spdx  spdx3  json  markdown  asciidoc  html  csv')
    ..addOption('name', abbr: 'n',
        help: 'Nom du document SBOM de sortie (remplace celui du fichier source).')
    ..addOption(
      'cyclonedx-version',
      defaultsTo: '1.6',
      allowed: _validCycloneDxVersions,
      help: 'Version CycloneDX cible quand -f inclut "cyclonedx" (défaut : 1.6).',
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
  if (args['help'] as bool) { _printConvertUsage(parser); exit(0); }

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
      stderr.writeln('convert: format inconnu "$f". Valides : ${_validFormats.join(', ')}');
      exit(1);
    }
  }

  if (!await File(inputPath).exists()) {
    stderr.writeln('convert: fichier introuvable : $inputPath');
    exit(1);
  }

  final Map<String, dynamic> json;
  try {
    json = await SbomReader.loadJson(inputPath);
  } catch (e) {
    stderr.writeln('convert: impossible de lire le JSON : $e');
    exit(1);
  }

  final reader = SbomReader();
  final format = SbomReader.detectFormat(json);
  if (format == SbomFormat.unknown) {
    stderr.writeln('convert: format SBOM non reconnu dans $inputPath');
    stderr.writeln('  Formats supportés : CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD');
    exit(1);
  }

  final List<Package> packages;
  try {
    packages = reader.read(json);
  } catch (e) {
    stderr.writeln('convert: erreur de lecture : $e');
    exit(1);
  }

  final name = docName ?? reader.documentName(json);
  final formatLabel = switch (format) {
    SbomFormat.cyclonedx => 'CycloneDX',
    SbomFormat.spdx2 => 'SPDX 2.x',
    SbomFormat.spdx3 => 'SPDX 3.0',
    SbomFormat.unknown => '?',
  };
  print('Conversion : $inputPath ($formatLabel, ${packages.length} composant(s))');

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
      stderr.writeln('convert: échec de l\'écriture ($fmt) : $e');
      exit(1);
    }
    final sz = await File(outPath).length();
    print('→ $outPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
  }
}

void _printConvertUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator convert – Convertit un fichier SBOM vers un ou plusieurs formats.

Usage:
  sbom_generator convert -i source.cdx.json -f spdx -o output.spdx.json
  sbom_generator convert -i source.spdx.json -f cyclonedx,csv -o output

Formats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD
Formats cible supportés  : cyclonedx, spdx, spdx3, json, markdown, asciidoc, html, csv

${parser.usage}
''');
}

// ── Sous-commande licenses ─────────────────────────────────────────────────────

Future<void> _runLicenses(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('input', abbr: 'i', mandatory: true,
        help: 'Fichier SBOM source (CycloneDX JSON ou SPDX JSON/JSON-LD).')
    ..addOption('output', abbr: 'o', mandatory: true,
        help: 'Fichier AsciiDoc de sortie (ex : licences.adoc).')
    ..addOption('name', abbr: 'n',
        help: 'Nom du document (remplace celui du fichier source).')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('licenses: ${e.message}');
    _printLicensesUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) { _printLicensesUsage(parser); exit(0); }

  final inputPath = args['input'] as String;
  final outputPath = args['output'] as String;
  final docName = args['name'] as String?;

  if (!await File(inputPath).exists()) {
    stderr.writeln('licenses: fichier introuvable : $inputPath');
    exit(1);
  }

  final Map<String, dynamic> json;
  try {
    json = await SbomReader.loadJson(inputPath);
  } catch (e) {
    stderr.writeln('licenses: impossible de lire le JSON : $e');
    exit(1);
  }

  final reader = SbomReader();
  final format = SbomReader.detectFormat(json);
  if (format == SbomFormat.unknown) {
    stderr.writeln('licenses: format SBOM non reconnu dans $inputPath');
    stderr.writeln('  Formats supportés : CycloneDX JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD');
    exit(1);
  }

  final List<Package> packages;
  try {
    packages = reader.read(json);
  } catch (e) {
    stderr.writeln('licenses: erreur de lecture : $e');
    exit(1);
  }

  final name = docName ?? reader.documentName(json);
  print('Rapport de licences : $inputPath (${packages.length} composant(s))');

  try {
    await LicenseReportGenerator()
        .writeToFile(packages, outputPath, documentName: name);
  } catch (e) {
    stderr.writeln('licenses: échec de l\'écriture : $e');
    exit(1);
  }

  final sz = await File(outputPath).length();
  print('→ $outputPath  (${(sz / 1024).toStringAsFixed(1)} KB)');
}

void _printLicensesUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator licenses – Génère un rapport de licences AsciiDoc à partir d'un fichier SBOM.

Le rapport regroupe les paquets par licence, avec un résumé et des
avertissements pour les licences copyleft (GPL/AGPL/LGPL/MPL/EPL/CDDL/CPL/EUPL)
et les paquets sans licence détectée.

Usage:
  sbom_generator licenses -i sbom.cdx.json -o licences.adoc
  sbom_generator licenses -i sbom.spdx.json -o licences.adoc -n "Mon projet"

Formats source supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD

${parser.usage}
''');
}

// ── Sous-commande validate ────────────────────────────────────────────────────

Future<void> _runValidate(List<String> arguments) async {
  final parser = ArgParser()
    ..addFlag('strict', defaultsTo: false, negatable: false,
        help: 'En mode strict, les champs recommandés (mais non obligatoires) '
            'génèrent aussi des erreurs.')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Aide.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on ArgParserException catch (e) {
    stderr.writeln('validate: ${e.message}');
    _printValidateUsage(parser);
    exit(1);
  }
  if (args['help'] as bool) { _printValidateUsage(parser); exit(0); }

  final files = args.rest;
  if (files.isEmpty) {
    stderr.writeln('validate: au moins un fichier SBOM requis.');
    _printValidateUsage(parser);
    exit(1);
  }

  final strict = args['strict'] as bool;
  int totalErrors = 0;

  for (final path in files) {
    if (!await File(path).exists()) {
      print('$path : ERREUR — fichier introuvable');
      totalErrors++;
      continue;
    }

    final Map<String, dynamic> json;
    try {
      json = await SbomReader.loadJson(path);
    } catch (e) {
      print('$path : ERREUR — JSON invalide : $e');
      totalErrors++;
      continue;
    }

    final errors = _validateSbom(json, strict: strict);
    final format = SbomReader.detectFormat(json);
    final label = switch (format) {
      SbomFormat.cyclonedx => 'CycloneDX ${json['specVersion'] ?? ''}',
      SbomFormat.spdx2 => 'SPDX ${json['spdxVersion'] ?? ''}',
      SbomFormat.spdx3 => 'SPDX 3.0 JSON-LD',
      SbomFormat.unknown => 'format inconnu',
    };

    if (errors.isEmpty) {
      print('$path : OK ($label)');
    } else {
      print('$path : $label — ${errors.length} erreur(s) :');
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
      errors.add(
          'Aucun indicateur de format reconnu. '
          'Attendu : bomFormat="CycloneDX", spdxVersion ou @context/@graph.');
  }
  return errors;
}

void _validateCycloneDx(
    Map<String, dynamic> json, List<String> errors, {bool strict = false}) {
  if (json['bomFormat'] != 'CycloneDX') {
    errors.add('bomFormat doit être "CycloneDX"');
  }
  if (json['specVersion'] == null) errors.add('specVersion manquant');
  if (json['version'] == null && strict) errors.add('[strict] version manquant');
  if (json['serialNumber'] == null && strict) {
    errors.add('[strict] serialNumber manquant');
  }

  final components = json['components'];
  if (components != null && components is! List) {
    errors.add('components doit être un tableau JSON');
  } else if (components is List) {
    for (int i = 0; i < components.length; i++) {
      final c = components[i];
      if (c is! Map) continue;
      if (c['name'] == null || (c['name'] as String).isEmpty) {
        errors.add('composant[$i] : champ name manquant ou vide');
      }
      if (c['type'] == null) {
        errors.add('composant[$i] (${c['name'] ?? '?'}) : champ type manquant');
      }
      if (strict && c['version'] == null) {
        errors.add('[strict] composant[$i] (${c['name'] ?? '?'}) : version manquante');
      }
    }
  }
}

void _validateSpdx2(
    Map<String, dynamic> json, List<String> errors, {bool strict = false}) {
  final ver = json['spdxVersion'] as String?;
  if (ver == null || !ver.startsWith('SPDX-')) {
    errors.add('spdxVersion manquant ou invalide (attendu : SPDX-2.x)');
  }
  if (json['SPDXID'] != 'SPDXRef-DOCUMENT') {
    errors.add('SPDXID doit être "SPDXRef-DOCUMENT"');
  }
  if (json['name'] == null) errors.add('name manquant');
  if (json['dataLicense'] == null) errors.add('dataLicense manquant');
  if (strict && json['creationInfo'] == null) {
    errors.add('[strict] creationInfo manquant');
  }

  final packages = json['packages'];
  if (packages is List) {
    for (int i = 0; i < packages.length; i++) {
      final p = packages[i] as Map?;
      if (p == null) continue;
      if (p['SPDXID'] == null) errors.add('packages[$i] : SPDXID manquant');
      if (p['name'] == null) errors.add('packages[$i] : name manquant');
      if (p['versionInfo'] == null && strict) {
        errors.add('[strict] packages[$i] (${p['name'] ?? '?'}) : versionInfo manquant');
      }
    }
  }
}

void _validateSpdx3(
    Map<String, dynamic> json, List<String> errors, {bool strict = false}) {
  if (json['@context'] == null) errors.add('@context manquant');
  final graph = json['@graph'];
  if (graph == null) {
    errors.add('@graph manquant');
    return;
  }
  if (graph is! List) {
    errors.add('@graph doit être un tableau JSON');
    return;
  }
  final hasDoc = graph.any((node) =>
      node is Map && (node['type'] as String?) == 'SpdxDocument');
  if (!hasDoc) {
    errors.add('@graph ne contient pas d\'élément SpdxDocument');
  }
  for (int i = 0; i < graph.length; i++) {
    final node = graph[i] as Map?;
    if (node == null) continue;
    if (node['spdxId'] == null && strict) {
      errors.add('[strict] @graph[$i] : spdxId manquant');
    }
  }
}

void _printValidateUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator validate – Vérifie la structure d'un ou plusieurs fichiers SBOM.

Usage:
  sbom_generator validate <fichier1.cdx.json> [fichier2.spdx.json ...]

Formats supportés : CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0 JSON-LD

${parser.usage}

Codes de retour:
  0  Tous les fichiers sont valides
  1  Au moins un fichier est invalide ou introuvable
''');
}

void _printUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator – Generate an SBOM from a list of packages or an OCI container image.

Usage:
  dart run bin/sbom_generator.dart --input <file> [options]
  dart run bin/sbom_generator.dart --image <ref>  [options]
  dart run bin/sbom_generator.dart --image <ref> --input <file> [options]

${parser.usage}

Input file format (--input) :
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

OCI image formats (--image) :
    • Registre  : nginx:latest  ubuntu:22.04  myregistry.io/app@sha256:…
    • Archive   : /path/image.tar          (docker save / skopeo docker-archive)
    • OCI layout: /path/to/oci_dir/        (directory containing index.json)

Examples:
  # CycloneDX depuis une image Docker Hub (via syft, défaut)
  dart run bin/sbom_generator.dart --image nginx:latest -o nginx.cdx.json

  # SPDX 2.3 depuis une archive tar, backend trivy
  dart run bin/sbom_generator.dart --image ./ubuntu.tar --oci-tool trivy -f spdx -o sbom.spdx.json

  # OCI layout directory, backend skopeo
  dart run bin/sbom_generator.dart --image ./oci_layout/ --oci-tool skopeo -o sbom.cdx.json

  # Combiner image OCI + liste de paquets supplémentaires
  dart run bin/sbom_generator.dart --image nginx:latest -i extra_pkgs.txt -o sbom.cdx.json

  # Multi-format en un seul passage
  dart run bin/sbom_generator.dart --image nginx:latest -f cyclonedx,spdx,markdown -o sbom

  # Depuis un fichier de paquets (mode classique)
  dart run bin/sbom_generator.dart -i packages.txt -o sbom.cdx.json
''');
}
