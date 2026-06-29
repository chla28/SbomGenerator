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
import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/spdx_generator.dart';
import 'package:sbom_generator/spdx3_generator.dart';
import 'package:sbom_generator/simple_json_generator.dart';
import 'package:sbom_generator/markdown_generator.dart';
import 'package:sbom_generator/asciidoc_generator.dart';
import 'package:sbom_generator/oci_parser.dart';
import 'package:sbom_generator/sbom_diff.dart';
import 'package:sbom_generator/sbom_merger.dart';
import 'package:sbom_generator/policy_checker.dart';

const _version = '1.0.0';

const _validFormats = {'cyclonedx', 'spdx', 'spdx3', 'json', 'markdown', 'asciidoc'};
const _validScanners = {'grype', 'osv', 'trivy', 'all'};
const _validOciTools = {'syft', 'trivy', 'skopeo'};
const _validDateFields = {'published', 'modified', 'latest'};

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

  final parser = ArgParser()
    ..addOption(
      'input',
      abbr: 'i',
      help: 'Input file containing one package reference per line.\n'
          'Each line may be:\n'
          '  • an RPM package name, NEVRA, or path to a .rpm file\n'
          '  • a path to a Debian .deb file\n'
          '  • a path to a Python .whl file\n'
          '  • a path to a requirements.txt file\n'
          '  • a path to a .tar / .tar.gz / .tgz / .zip archive\n'
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
          '  cyclonedx  CycloneDX 1.6 JSON (default)\n'
          '  spdx       SPDX 2.3 JSON\n'
          '  spdx3      SPDX 3.0 JSON-LD\n'
          '  json       Custom human-friendly JSON\n'
          '  markdown   Tableau Markdown des licences\n'
          '  asciidoc   Tableau AsciiDoc des licences\n'
          'Example: -f cyclonedx,spdx,markdown',
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

  if (inputPath != null) {
    final inputFile = File(inputPath);
    if (!await inputFile.exists()) {
      _err('Input file not found: $inputPath');
      exit(1);
    }
  }

  // --- Read package list (optionnel si --image est fourni) ---
  List<String> packageRefs = [];
  if (inputPath != null) {
    final lines = await File(inputPath).readAsLines();
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

  // --- Expand requirements.txt files (preprocess before the main loop) ---
  final reqParser = RequirementsParser();
  final preloadedPackages = <Package>[];
  final filteredRefs = <String>[];
  for (final ref in packageRefs) {
    if (_isRequirements(ref)) {
      preloadedPackages.addAll(reqParser.parseFile(ref));
    } else {
      filteredRefs.add(ref);
    }
  }
  final mainRefs = filteredRefs;

  // --- Analyse OCI image ---
  final ociPackages = <Package>[];
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
      ociPackages.addAll(
          await OciParser().parseImage(imageRef, ociTool, verbose: verbose));
      print('${ociPackages.length} paquet(s) trouvé(s) dans l\'image.');
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
      !r.endsWith('.zip'));
  final hasWhl = mainRefs.any((r) => r.endsWith('.whl'));
  final hasTar = mainRefs.any(_isTar);
  final hasZip = mainRefs.any((r) => r.endsWith('.zip'));
  final hasDeb = mainRefs.any((r) => r.endsWith('.deb'));

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

  final mainTotal = mainRefs.length;
  final sem = _Semaphore(
      concurrencyN == 0 ? mainTotal.clamp(1, 1 << 20) : concurrencyN);
  int completed = 0;

  final rawResults = await Future.wait(
    List<Future<Package?>>.generate(mainTotal, (i) async {
      var ref = mainRefs[i];

      // Resolve bare RPM name to a local file when --rpm-dir is set
      if (rpmDir != null &&
          !ref.contains('/') &&
          !ref.endsWith('.whl') &&
          !ref.endsWith('.deb') &&
          !ref.endsWith('.zip') &&
          !_isTar(ref)) {
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
        Package? pkg;
        if (ref.endsWith('.whl')) {
          pkg = await whlParser.parseWheelFile(ref);
        } else if (_isTar(ref)) {
          pkg = await tarParser.parseTarFile(ref);
        } else if (ref.endsWith('.zip')) {
          pkg = await zipParser.parseZipFile(ref);
        } else if (ref.endsWith('.deb')) {
          pkg = await debParser.parseDebFile(ref);
        } else {
          pkg = await rpmParser.parsePackage(ref);
        }
        completed++;
        final label = ref.contains('/') ? ref.split('/').last : ref;
        _printProgress(completed, mainTotal, label);
        return pkg;
      } finally {
        sem.release();
      }
    }),
  );

  if (mainTotal > 0) stdout.writeln();

  final packages = <Package>[];
  final failedRefs = <String>[];
  for (int i = 0; i < rawResults.length; i++) {
    final pkg = rawResults[i];
    if (pkg != null) {
      packages.add(pkg);
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
  if (formats.any((f) => f != 'markdown' && f != 'asciidoc')) {
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
              uniquePackages, dependencies, outPath, documentName: docName);
        case 'spdx':
          await SpdxGenerator().writeToFile(
              uniquePackages, dependencies, outPath, documentName: docName);
        case 'spdx3':
          await Spdx3Generator().writeToFile(
              uniquePackages, dependencies, outPath, documentName: docName);
        case 'json':
          await SimpleJsonGenerator().writeToFile(
              uniquePackages, dependencies, outPath, documentName: docName);
        case 'markdown':
          await MarkdownGenerator()
              .writeToFile(uniquePackages, outPath, documentName: docName);
        case 'asciidoc':
          await AsciidocGenerator()
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
        help: 'Fichier SBOM fusionné de sortie (.cdx.json).')
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
  final total = (merged['components'] as List).length;
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

bool _isRequirements(String ref) =>
    ref.endsWith('.txt') && !ref.endsWith('.whl');

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

  if (!_validScanners.contains(scanner)) {
    stderr.writeln('scan: scanner invalide "$scanner". Valides : ${_validScanners.join(', ')}');
    exit(1);
  }
  if (!_validDateFields.contains(dateField)) {
    stderr.writeln('scan: cve-date-field invalide "$dateField". Valides : ${_validDateFields.join(', ')}');
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

  int totalShown = 0;
  for (final s in scanners) {
    final vulns = await _runScanner(s, sbomFile);
    if (vulns == null) continue;

    final filtered = _filterByDate(vulns, dateField, after, before, includeUndated);
    _printScanResults(s, filtered, after, before, dateField);
    totalShown += filtered.length;
  }

  exit(totalShown > 0 ? 1 : 0);
}

// Retourne la liste brute [{id, severity, package, published, modified}] ou null si erreur.
Future<List<Map<String, dynamic>>?>  _runScanner(String scanner, String sbomFile) async {
  switch (scanner) {
    case 'grype':
      return _runGrype(sbomFile);
    case 'osv':
      return _runOsv(sbomFile);
    case 'trivy':
      return _runTrivy(sbomFile);
    default:
      return null;
  }
}

Future<List<Map<String, dynamic>>?> _runGrype(String sbomFile) async {
  stdout.writeln('\n── Grype ──────────────────────────────────────────');
  final result = await Process.run('grype', [sbomFile, '--output', 'json']);
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

Future<List<Map<String, dynamic>>?> _runOsv(String sbomFile) async {
  stdout.writeln('\n── OSV-Scanner ─────────────────────────────────────');
  final result = await Process.run('osv-scanner', ['--format', 'json', '--sbom', sbomFile]);
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

Future<List<Map<String, dynamic>>?> _runTrivy(String sbomFile) async {
  stdout.writeln('\n── Trivy ───────────────────────────────────────────');
  final result = await Process.run('trivy', ['sbom', '--format', 'json', '--quiet', sbomFile]);
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

Codes de retour:
  0  Aucune CVE dans la plage demandée
  1  Au moins une CVE trouvée (ou erreur de scanner)
''');
}

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
