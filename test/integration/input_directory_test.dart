/// Integration test exercising the real CLI on a directory passed to
/// --input, covering recursive discovery of mixed package/manifest files
/// (including .jar) introduced alongside JarParser.
///
/// Requires `dart run` to work and `unzip` in PATH (used by JarParser).
/// Skipped automatically when unzip is absent.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

Future<bool> _hasUnzip() async {
  try {
    final r = await Process.run('unzip', ['-v']);
    return r.exitCode == 0;
  } on ProcessException {
    return false;
  }
}

void main() {
  late bool hasUnzip;
  late Directory tmp;

  setUpAll(() async {
    hasUnzip = await _hasUnzip();
  });

  setUp(() => tmp = Directory.systemTemp.createTempSync('input_dir_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  test(
      '--input <dossier> scanne récursivement jar + requirements.txt et ignore le reste',
      () async {
    if (!hasUnzip) {
      markTestSkipped('unzip absent — test d\'intégration ignoré');
      return;
    }

    final libsDir = Directory('${tmp.path}/libs')..createSync();
    File('${libsDir.path}/org.apache.commons.commons-lang3-3.14.0.jar')
        .writeAsBytesSync([]);

    final reqsDir = Directory('${tmp.path}/reqs')..createSync();
    File('${reqsDir.path}/requirements.txt')
        .writeAsStringSync('requests==2.31.0\n');
    File('${reqsDir.path}/notes.txt').writeAsStringSync('à ignorer\n');

    final outPath = '${tmp.path}/out.cdx.json';
    final result = await Process.run(
      'dart',
      [
        'run',
        'bin/sbom_generator.dart',
        '--lang',
        'fr',
        '--input',
        tmp.path,
        '-o',
        outPath
      ],
      workingDirectory: Directory.current.path,
    );

    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');

    final doc =
        jsonDecode(await File(outPath).readAsString()) as Map<String, dynamic>;
    // Les composants Maven séparent groupId (champ `group`) et artifactId
    // (`name`), suivant la convention CycloneDX — recombinés ici pour
    // comparaison, comme le fait SbomReader à la relecture.
    final names = (doc['components'] as List).map((c) {
      final map = c as Map;
      final group = map['group'] as String?;
      final name = map['name'] as String;
      return group != null ? '$group:$name' : name;
    }).toSet();

    expect(names, {
      'org.apache.commons:commons-lang3',
      'requests',
    });
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('--input <dossier> reconnaît NuGet, Swift et les lockfiles Python TOML',
      () async {
    File('${tmp.path}/packages.lock.json').writeAsStringSync(jsonEncode({
      'version': 1,
      'dependencies': {
        'net8.0': {
          'Newtonsoft.Json': {'type': 'Direct', 'resolved': '13.0.1'},
        },
      },
    }));
    File('${tmp.path}/Package.resolved').writeAsStringSync(jsonEncode({
      'version': 2,
      'pins': [
        {
          'identity': 'swift-nio',
          'location': 'https://github.com/apple/swift-nio.git',
          'state': {'version': '2.62.0'},
        },
      ],
    }));
    File('${tmp.path}/uv.lock')
        .writeAsStringSync('[[package]]\nname = "idna"\nversion = "3.6"\n');

    final outPath = '${tmp.path}/out.cdx.json';
    final result = await Process.run(
      'dart',
      [
        'run',
        'bin/sbom_generator.dart',
        '--lang',
        'fr',
        '--input',
        tmp.path,
        '-o',
        outPath
      ],
      workingDirectory: Directory.current.path,
    );
    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');

    final doc =
        jsonDecode(await File(outPath).readAsString()) as Map<String, dynamic>;
    final purls = (doc['components'] as List)
        .map((c) => (c as Map)['purl'] as String)
        .toSet();
    expect(purls, {
      'pkg:nuget/Newtonsoft.Json@13.0.1',
      'pkg:swift/github.com/apple/swift-nio@2.62.0',
      'pkg:pypi/idna@3.6',
    });
  }, timeout: const Timeout(Duration(seconds: 60)));
}
