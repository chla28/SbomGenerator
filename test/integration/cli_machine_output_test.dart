/// Sorties lisibles par une machine : `validate --format json`,
/// `--log-format json` (NDJSON) à la génération, sous-commande `vex`.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('cli_machine_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> cli(List<String> args) => Process.run(
      'dart', ['run', 'bin/sbom_generator.dart', '--lang', 'en', ...args]);

  File write(String name, Object json) =>
      File('${tmp.path}/$name')..writeAsStringSync(jsonEncode(json));

  test('--log-format json : stdout ne contient que du NDJSON', () async {
    final out = '${tmp.path}/sbom';
    final r = await cli([
      '-i',
      'pubspec.lock',
      '-f',
      'cyclonedx,spdx',
      '-o',
      out,
      '--log-format',
      'json',
    ]);
    expect(r.exitCode, 0);
    final events = [
      for (final l in const LineSplitter().convert(r.stdout as String))
        jsonDecode(l) as Map<String, dynamic>,
    ];
    final outputs = events.where((e) => e['event'] == 'output').toList();
    expect(outputs.map((e) => (e['path'] as String).split('/').last),
        ['sbom.cdx.json', 'sbom.spdx.json']);
    expect(
        events.every(
            (e) => const {'output', 'progress', 'log'}.contains(e['event'])),
        isTrue);
  });

  test('validate --format json : fichier valide et invalide', () async {
    final ok = write('ok.cdx.json', {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'version': 1,
      'components': [
        {'type': 'library', 'name': 'a', 'version': '1'},
      ],
    });
    final bad = write('bad.cdx.json', {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'components': [
        {'name': 'a'},
      ],
    });
    final r = await cli(['validate', '--format', 'json', ok.path, bad.path]);
    expect(r.exitCode, 1);
    final j = jsonDecode(r.stdout as String) as Map<String, dynamic>;
    expect(j['valid'], isFalse);
    final files = j['files'] as List;
    expect(files[0]['valid'], isTrue);
    expect(files[0]['schema'], 'cyclonedx-1.6');
    expect(files[1]['valid'], isFalse);
    expect((files[1]['errors'] as List).join(' '), contains('[schema]'));
  });

  test('validate --no-schema : contrôles structurels seuls', () async {
    final f = write('x.cdx.json', {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'components': [
        {'type': 'library', 'name': 'a', 'unknownField': 1},
      ],
    });
    expect((await cli(['validate', f.path])).exitCode, 1,
        reason: 'additionalProperties refusé par le schéma');
    expect((await cli(['validate', '--no-schema', f.path])).exitCode, 0);
  });

  test('sortie sans extension : `-o sbom` produit sbom.cdx.json', () async {
    final r = await cli(
        ['-i', 'pubspec.lock', '-f', 'cyclonedx', '-o', '${tmp.path}/sbom']);
    expect(r.exitCode, 0);
    expect(File('${tmp.path}/sbom.cdx.json').existsSync(), isTrue);
    expect(File('${tmp.path}/sbom').existsSync(), isFalse);
  });

  group('vex', () {
    test('crée un OpenVEX puis y ajoute une déclaration (CycloneDX)', () async {
      final a = '${tmp.path}/a.json';
      var r = await cli([
        'vex',
        '-c',
        'CVE-1',
        '-p',
        'pkg:npm/foo@1.0.0',
        '-s',
        'not_affected',
        '--justification',
        'component_not_present',
        '-o',
        a,
      ]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final b = '${tmp.path}/b.json';
      r = await cli([
        'vex',
        '-c',
        'CVE-2',
        '-s',
        'affected',
        '--append',
        a,
        '-f',
        'cyclonedx',
        '-o',
        b,
      ]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final j = jsonDecode(File(b).readAsStringSync()) as Map;
      expect(j['bomFormat'], 'CycloneDX');
      expect((j['vulnerabilities'] as List).map((v) => v['id']),
          ['CVE-1', 'CVE-2']);
      expect((await cli(['validate', b])).exitCode, 0);
    });

    test('not_affected sans justification : refusé', () async {
      final r = await cli(['vex', '-c', 'CVE-1', '-s', 'not_affected']);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('requires --justification'));
    });
  });
}
