import 'dart:io';
import 'package:args/args.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/rpm_parser.dart';
import 'package:sbom_generator/wheel_parser.dart';
import 'package:sbom_generator/tar_parser.dart';
import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/spdx_generator.dart';
import 'package:sbom_generator/spdx3_generator.dart';
import 'package:sbom_generator/simple_json_generator.dart';
import 'package:sbom_generator/markdown_generator.dart';

const _version = '1.0.0';

Future<void> main(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption(
      'input',
      abbr: 'i',
      help: 'Input file containing one package reference per line.\n'
          'Each line may be:\n'
          '  • an RPM package name, NEVRA, or path to a .rpm file\n'
          '  • a path to a Python .whl file',
    )
    ..addOption(
      'output',
      abbr: 'o',
      defaultsTo: 'sbom.json',
      help: 'Path for the generated SBOM file.',
    )
    ..addOption(
      'format',
      abbr: 'f',
      defaultsTo: 'cyclonedx',
      allowed: ['cyclonedx', 'spdx', 'spdx3', 'json', 'markdown'],
      allowedHelp: {
        'cyclonedx': 'CycloneDX 1.6 JSON  (default)',
        'spdx': 'SPDX 2.3 JSON',
        'spdx3': 'SPDX 3.0 JSON-LD',
        'json': 'Custom human-friendly JSON',
        'markdown': 'Tableau Markdown des licences',
      },
      help: 'Output SBOM format.',
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

  if (!args.wasParsed('input')) {
    _err('Missing required option --input.');
    _printUsage(parser);
    exit(1);
  }

  final inputPath = args['input'] as String;
  final outputPath = args['output'] as String;
  final format = args['format'] as String;
  final docName = args['name'] as String?;
  final verbose = args['verbose'] as bool;
  final rpmDir = args['rpm-dir'] as String?;

  final inputFile = File(inputPath);
  if (!await inputFile.exists()) {
    _err('Input file not found: $inputPath');
    exit(1);
  }

  // --- Read package list ---
  final lines = await inputFile.readAsLines();
  final packageRefs = lines
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty && !l.startsWith('#'))
      .toList();

  if (packageRefs.isEmpty) {
    _err('No packages found in $inputPath '
        '(empty file or all lines are comments).');
    exit(1);
  }

  // --- Build RPM file index from --rpm-dir ---
  final rpmExactIndex = <String, String>{};   // stem (without .rpm) → path
  final rpmNameIndex  = <String, List<String>>{}; // package name → sorted [paths]
  if (rpmDir != null) {
    final dir = Directory(rpmDir);
    if (!await dir.exists()) {
      _err('RPM directory not found: $rpmDir');
      exit(1);
    }
    await for (final entity in dir.list(recursive: true, followLinks: false)) {
      if (entity is File && entity.path.endsWith('.rpm')) {
        final stem = entity.path.split('/').last.replaceAll(RegExp(r'\.rpm$'), '');
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

  // --- Detect tool availability ---
  final hasRpm = packageRefs.any((r) => !r.endsWith('.whl') && !_isTar(r));
  final hasWhl = packageRefs.any((r) => r.endsWith('.whl'));
  final hasTar = packageRefs.any(_isTar);

  if (hasRpm) {
    final rpmCheck = await Process.run('rpm', ['--version']);
    if (rpmCheck.exitCode != 0) {
      _err('rpm binary not found or not functional.');
      exit(1);
    }
    if (verbose) print('rpm: ${(rpmCheck.stdout as String).trim()}');
  }

  if (hasWhl || hasTar) {
    final py3Check = await Process.run('python3', ['--version']);
    if (py3Check.exitCode != 0) {
      _err('python3 not found — required to read .whl and tar archive files.');
      exit(1);
    }
    if (verbose) print('python3: ${(py3Check.stdout as String).trim()}');
  }

  // --- Parse packages ---
  final total = packageRefs.length;
  print('Querying $total package(s)…');

  final rpmParser = RpmParser();
  final whlParser = WheelParser();
  final tarParser = TarParser();
  final packages = <Package>[];
  int failed = 0;

  for (int i = 0; i < total; i++) {
    var ref = packageRefs[i];

    // Resolve bare RPM name to a local file when --rpm-dir is set
    if (rpmDir != null &&
        !ref.contains('/') &&
        !ref.endsWith('.whl') &&
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

    final label = ref.contains('/') ? ref.split('/').last : ref;
    _printProgress(i, total, label);

    Package? pkg;
    if (ref.endsWith('.whl')) {
      pkg = await whlParser.parseWheelFile(ref);
    } else if (_isTar(ref)) {
      pkg = await tarParser.parseTarFile(ref);
    } else {
      pkg = await rpmParser.parsePackage(ref);
    }

    if (pkg != null) {
      packages.add(pkg);
    } else {
      failed++;
    }
  }

  _printProgress(total, total, 'terminé');
  stdout.writeln();

  // --- Deduplicate ---
  final seenRefs = <String>{};
  final uniquePackages = <Package>[];
  int dupes = 0;
  for (final pkg in packages) {
    if (seenRefs.add(pkg.bomRef)) {
      uniquePackages.add(pkg);
    } else {
      dupes++;
    }
  }

  final failedNote = failed > 0 ? '  ($failed échec(s))' : '';
  final dupeNote = dupes > 0 ? '  ($dupes doublon(s) supprimé(s))' : '';
  print('Analysés : ${uniquePackages.length}/$total paquet(s).$failedNote$dupeNote');

  if (uniquePackages.isEmpty) {
    _err('No packages could be parsed. Aborting.');
    exit(1);
  }

  // --- Build dependency graph (skipped for markdown) ---
  final dependencies = <PackageDependency>[];
  if (format != 'markdown') {
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

  // --- Generate SBOM ---
  print('Generating SBOM ($format format)…');
  try {
    switch (format) {
      case 'cyclonedx':
        await CycloneDxGenerator().writeToFile(
          uniquePackages, dependencies, outputPath,
          documentName: docName,
        );
      case 'spdx':
        await SpdxGenerator().writeToFile(
          uniquePackages, dependencies, outputPath,
          documentName: docName,
        );
      case 'spdx3':
        await Spdx3Generator().writeToFile(
          uniquePackages, dependencies, outputPath,
          documentName: docName,
        );
      case 'json':
        await SimpleJsonGenerator().writeToFile(
          uniquePackages, dependencies, outputPath,
          documentName: docName,
        );
      case 'markdown':
        await MarkdownGenerator().writeToFile(
          uniquePackages, outputPath,
          documentName: docName,
        );
    }
  } catch (e, st) {
    _err('Failed to write SBOM: $e');
    if (verbose) stderr.writeln(st);
    exit(1);
  }

  final outputSize = await File(outputPath).length();
  final sizeKb = (outputSize / 1024).toStringAsFixed(1);
  print('SBOM written → $outputPath  ($sizeKb KB)');
}

bool _isTar(String ref) =>
    ref.endsWith('.tar') || ref.endsWith('.tar.gz') || ref.endsWith('.tgz');

void _err(String msg) => stderr.writeln('Error: $msg');

void _printProgress(int current, int total, String label) {
  const barWidth = 32;

  final ratio = total == 0 ? 1.0 : current / total;
  final filled = (ratio * barWidth).round().clamp(0, barWidth);
  final bar = '${'█' * filled}${'░' * (barWidth - filled)}';

  final pct = '${(ratio * 100).round().toString().padLeft(3)}%';
  final count =
      '${current.toString().padLeft(total.toString().length)}/$total';

  const prefix = '  ';
  final head = '[$bar] $count  $pct  ';
  final maxLabel = 120 - prefix.length - head.length;
  final shortLabel = label.length > maxLabel
      ? '…${label.substring(label.length - maxLabel + 1)}'
      : label;

  stdout.write('\r$prefix$head$shortLabel\x1B[K');
}

void _printUsage(ArgParser parser) {
  stdout.writeln('''
sbom_generator – Generate an SBOM from a list of RPM and/or Python wheel packages.

Usage:
  dart run bin/sbom_generator.dart --input <file> [options]
  dart compile exe bin/sbom_generator.dart -o sbom_generator && ./sbom_generator --input <file>

${parser.usage}

Input file format:
  One package reference per line. Lines starting with # are ignored.
  References can be mixed:
    • RPM: installed package name/NEVRA, or path to a .rpm file
    • Python wheel: path to a .whl file
    • Source archive: path to a .tar, .tar.gz or .tgz file
        - Python sdist (PKG-INFO present) → PURL pkg:pypi/…
        - Generic archive (no metadata)   → PURL pkg:generic/…, name/version
                                            derived from the filename

  Example input.txt:
    # RPM packages (bare name resolved via --rpm-dir, or queried from installed DB)
    bash
    glibc
    /tmp/mypkg-1.0-1.el9.x86_64.rpm
    # Python wheel
    /opt/wheels/requests-2.28.0-py3-none-any.whl
    # Python sdist / generic archives
    /opt/src/Django-4.2.tar.gz
    /opt/src/libfoo-1.2.3.tar.gz

Examples:
  # CycloneDX (default)
  dart run bin/sbom_generator.dart -i packages.txt -o sbom.cdx.json

  # SPDX 2.3
  dart run bin/sbom_generator.dart -i packages.txt -f spdx -o sbom.spdx.json

  # SPDX 3.0 JSON-LD
  dart run bin/sbom_generator.dart -i packages.txt -f spdx3 -o sbom.spdx3.jsonld

  # Simple JSON with a custom name
  dart run bin/sbom_generator.dart -i packages.txt -f json -n "My App" -o sbom.json -v

  # Tableau Markdown des licences
  dart run bin/sbom_generator.dart -i packages.txt -f markdown -o licences.md

  # Résoudre les noms RPM nus depuis un dossier local
  dart run bin/sbom_generator.dart -i packages.txt -d /mnt/repo -o sbom.cdx.json
''');
}
