/// Sous-commande `report` : même rapport que `scan --format asciidoc`, à
/// partir d'un fichier de résultats (aucun scanner lancé).
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('report_cmd_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> cli(List<String> args, {Map<String, String>? env}) =>
      Process.run(
          'dart', ['run', 'bin/sbom_generator.dart', '--lang', 'en', ...args],
          environment: env);

  File write(String name, Object json) =>
      File('${tmp.path}/$name')..writeAsStringSync(jsonEncode(json));

  Map<String, dynamic> finding(String id, String sev, String pkg) => {
        'scanner': 'grype',
        'id': id,
        'severity': sev,
        'package': pkg,
        'fixedVersions': ['9.9'],
        'fixState': 'fixed',
      };

  test('JSON de scan → rapport AsciiDoc complet, seuil appliqué', () async {
    final f = write('r.json', {
      'schema': 'sbom-generator/scan/v1',
      'generatedAt': '2026-03-01T00:00:00Z',
      'target': 'x.cdx.json',
      'scanners': ['grype'],
      'findings': [
        finding('CVE-1', 'Critical', 'a@1'),
        finding('CVE-2', 'Low', 'b@1'),
      ],
    });
    final out = '${tmp.path}/out.adoc';
    var r = await cli(['report', '-i', f.path, '-f', 'asciidoc', '-o', out]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    var adoc = File(out).readAsStringSync();
    expect(adoc, contains('== Executive summary'));
    expect(adoc, contains('== Remediation'));
    expect(adoc, contains('=== CVE-2'));

    r = await cli(
        ['report', '-i', f.path, '-f', 'asciidoc', '-s', 'high', '-o', out]);
    adoc = File(out).readAsStringSync();
    expect(adoc, contains('=== CVE-1'));
    expect(adoc, isNot(contains('=== CVE-2')));
    expect(adoc, contains('1 of 2 unique CVEs'));
  });

  test('session de la GUI acceptée ; --compare-with ; Markdown', () async {
    final session = write('s.json', {
      'format': 1,
      'savedAt': '2026-03-01T00:00:00Z',
      'guiVersion': '1.8.0',
      'targets': ['SBOM a.cdx.json'],
      'trivy': [
        {
          'id': 'CVE-5',
          'severity': 'HIGH',
          'package': 'p',
          'version': '1',
          'fixed': '2',
          'title': 'Une description assez longue de la CVE',
        },
      ],
      'exploit': {},
    });
    final old = write('old.json', {
      'format': 1,
      'savedAt': '2026-01-01T00:00:00Z',
      'trivy': [],
    });
    final out = '${tmp.path}/out.md';
    final r = await cli([
      'report', '-i', session.path, '--compare-with', old.path, //
      '-f', 'markdown', '-o', out,
    ]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    final md = File(out).readAsStringSync();
    expect(md, contains('## Trend'));
    expect(md, contains('**New:** 1'));
    expect(md, contains('CVE-5'));
  });

  test('--vex supplémentaire écarte la CVE ; --no-vex ignore l\'embarqué',
      () async {
    final f = write('r.json', {
      'schema': 'sbom-generator/scan/v1',
      'scanners': ['grype'],
      'findings': [finding('CVE-1', 'Critical', 'a@1')],
      'vex': [
        {'vulnId': 'CVE-1', 'status': 'fixed', 'products': []},
      ],
    });
    final out = '${tmp.path}/o.adoc';
    var r = await cli(['report', '-i', f.path, '-f', 'asciidoc', '-o', out]);
    expect(File(out).readAsStringSync(), isNot(contains('=== CVE-1')));
    r = await cli(
        ['report', '-i', f.path, '-f', 'asciidoc', '--no-vex', '-o', out]);
    expect(File(out).readAsStringSync(), contains('=== CVE-1'));
    final vex = write('v.json', {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      'statements': [
        {
          'vulnerability': {'name': 'CVE-1'},
          'status': 'not_affected',
          'justification': 'component_not_present',
        },
      ],
    });
    r = await cli([
      'report', '-i', f.path, '-f', 'asciidoc', '--no-vex', '--vex',
      vex.path, //
      '-o', out,
    ]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(File(out).readAsStringSync(), isNot(contains('=== CVE-1')),
        reason: 'le VEX fourni s\'applique même avec --no-vex');
  });

  test('fichier invalide ou introuvable : erreur claire, code 1', () async {
    final bad = write('bad.json', {'a': 1});
    var r = await cli(['report', '-i', bad.path, '-o', '${tmp.path}/x.adoc']);
    expect(r.exitCode, 1);
    expect(r.stderr, contains('unrecognised file'));
    r = await cli(['report', '-i', '${tmp.path}/absent.json', '-o', 'x']);
    expect(r.exitCode, 1);
    expect(r.stderr, contains('file not found'));
  });
}
