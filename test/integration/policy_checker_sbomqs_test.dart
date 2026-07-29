/// Integration test that runs the real sbomqs binary.
///
/// Requires sbomqs in PATH. Skipped automatically when sbomqs is absent.
@TestOn('posix')
library;

import 'dart:io';

import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/policy_checker.dart';
import 'package:test/test.dart';

Future<bool> _hasSbomqs() async {
  try {
    final r = await Process.run('sbomqs', ['version']);
    return r.exitCode == 0;
  } on ProcessException {
    return false;
  }
}

void main() {
  late bool hasSbomqs;
  late Directory tmpDir;

  setUpAll(() async {
    hasSbomqs = await _hasSbomqs();
  });

  setUp(() {
    tmpDir = Directory.systemTemp.createTempSync('policy_checker_test_');
  });

  tearDown(() {
    if (tmpDir.existsSync()) tmpDir.deleteSync(recursive: true);
  });

  group('PolicyChecker.runSbomqs', () {
    test('retourne un score entre 0 et 10 pour un SBOM valide', () async {
      if (!hasSbomqs) {
        markTestSkipped('sbomqs absent — test d\'intégration ignoré');
        return;
      }

      final pkg = RpmPackage(
        name: 'foo',
        version: '1.0',
        release: '1.el9',
        arch: 'x86_64',
        epoch: '(none)',
        license: 'MIT',
        vendor: 'Example',
        url: 'https://example.org/foo',
        buildTime: '',
        summary: 'Un paquet de test',
        requires: const [],
        provides: const [],
      );

      final sbomPath = '${tmpDir.path}/sbom.cdx.json';
      await CycloneDxGenerator().writeToFile(
        [pkg],
        const [],
        sbomPath,
        documentName: 'test-doc',
      );

      final score = await PolicyChecker().runSbomqs(sbomPath);

      expect(score, isNotNull);
      expect(score, inInclusiveRange(0, 10));
    });

    test('retourne null pour un fichier introuvable', () async {
      if (!hasSbomqs) {
        markTestSkipped('sbomqs absent — test d\'intégration ignoré');
        return;
      }

      final score =
          await PolicyChecker().runSbomqs('${tmpDir.path}/absent.cdx.json');
      expect(score, isNull);
    });
  });
}
