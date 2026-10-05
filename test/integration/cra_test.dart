/// Integration test for the `sbom_generator cra` subcommand — runs the real
/// CLI on a small CycloneDX SBOM, `--no-scan` (no external scanner needed).
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

const _richSbom = '''
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2026-09-08T10:00:00Z",
    "authors": [{"name": "CI"}],
    "component": {"type": "application", "name": "app", "version": "1.0"}
  },
  "components": [
    {
      "type": "library", "name": "lib-a", "version": "1.2.3",
      "purl": "pkg:pypi/lib-a@1.2.3",
      "supplier": {"name": "ACME"},
      "hashes": [{"alg": "SHA-256", "content": "deadbeef"}],
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ],
  "dependencies": [{"ref": "app", "dependsOn": ["lib-a"]}]
}
''';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('cra_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> runCra(List<String> extra) {
    final sbom = File('${tmp.path}/sbom.cdx.json')
      ..writeAsStringSync(_richSbom);
    return Process.run('dart', [
      'run',
      'bin/sbom_generator.dart',
      '--lang',
      'fr',
      'cra',
      '--sbom',
      sbom.path,
      '--no-scan',
      ...extra,
    ]);
  }

  test('--format json : structure + verdict, métadonnées via CLI', () async {
    final r = await runCra([
      '--format',
      'json',
      '--manufacturer',
      'ACME Corp',
      '--product',
      'WidgetOS',
      '--product-version',
      '3.2.1',
    ]);
    // Pas de point bloquant sur ce SBOM riche → exit 0 (partiel car pas de scan).
    expect(r.exitCode, 0);
    final j = jsonDecode((r.stdout as String)) as Map<String, dynamic>;
    expect(j['regulation'], 'EU 2024/2847');
    expect(j['product']['manufacturer'], 'ACME Corp');
    expect(j['verdict'], 'partial');
    expect(j['blockers'], isEmpty);
    expect((j['sbom']['fieldChecks'] as List).every((c) => c['status'] == 'ok'),
        isTrue);
    expect(j['vulnerabilities']['evaluated'], isFalse);
  });

  test('cra.yaml : métadonnées lues depuis le fichier', () async {
    File('${tmp.path}/cra.yaml')
        .writeAsStringSync('manufacturer: "Depuis YAML"\nproduct: FromYaml\n');
    final r =
        await runCra(['--format', 'json', '--config', '${tmp.path}/cra.yaml']);
    final j = jsonDecode((r.stdout as String)) as Map<String, dynamic>;
    expect(j['product']['manufacturer'], 'Depuis YAML');
    expect(j['product']['name'], 'FromYaml');
  });

  test('SBOM pauvre → non conforme (exit 2)', () async {
    final sbom = File('${tmp.path}/bare.cdx.json')
      ..writeAsStringSync(
          '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"x","version":"1"}]}');
    final r = await Process.run('dart', [
      'run',
      'bin/sbom_generator.dart',
      '--lang',
      'fr',
      'cra',
      '--sbom',
      sbom.path,
      '--no-scan',
      '--format',
      'json',
    ]);
    expect(r.exitCode, 2);
    final j = jsonDecode((r.stdout as String)) as Map<String, dynamic>;
    expect(j['verdict'], 'fail');
    expect(j['blockers'], isNotEmpty);
  });

  test('--format asciidoc : rapport écrit, en-tête CRA', () async {
    final out = '${tmp.path}/rapport.adoc';
    final r = await runCra(['--format', 'asciidoc', '-o', out]);
    expect(r.exitCode, anyOf(0, 2));
    final adoc = File(out).readAsStringSync();
    expect(adoc, startsWith('= Rapport de conformité: Cyber Resilience Act'));
    expect(adoc, contains(':title-page:'));
    expect(adoc, contains('== Portée et limites'));
    expect(adoc, contains('art. 14'));
  });
}
