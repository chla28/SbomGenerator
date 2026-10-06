/// `scan` : VEX, CVE ignorées, référence (baseline), seuil `--fail-on`, cache
/// et sortie JSON — avec un faux `grype` placé en tête du PATH (aucune base de
/// vulnérabilités ni réseau nécessaires).
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

const _matches = [
  ('CVE-2024-0001', 'Critical', 'liba', '1.0'),
  ('CVE-2024-0002', 'High', 'libb', '2.0'),
  ('CVE-2024-0003', 'Low', 'libc', '3.0'),
];

void main() {
  late Directory tmp;
  late Map<String, String> env;
  late String sbom;
  late File counter;

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('scan_policy_');
    final bin = Directory('${tmp.path}/bin')..createSync();
    counter = File('${tmp.path}/runs')..writeAsStringSync('');
    final grypeJson = jsonEncode({
      'matches': [
        for (final (id, sev, name, ver) in _matches)
          {
            'vulnerability': {
              'id': id,
              'severity': sev,
              'fix': {
                'state': 'fixed',
                'versions': ['9.9']
              },
            },
            'artifact': {'name': name, 'version': ver},
          },
      ],
    });
    File('${bin.path}/grype')
      ..writeAsStringSync('#!/bin/sh\n'
          'if [ "\$1" = "version" ]; then echo "Version: 0.99.0"; exit 0; fi\n'
          'echo run >> ${counter.path}\n'
          "cat <<'EOF'\n$grypeJson\nEOF\n"
          'exit 1\n')
      ..setLastModifiedSync(DateTime.now());
    Process.runSync('chmod', ['+x', '${bin.path}/grype']);
    env = {
      'PATH': '${bin.path}:${Platform.environment['PATH']}',
      'SBOMGEN_OFFLINE': '1',
      'XDG_CACHE_HOME': '${tmp.path}/cache',
    };
    sbom = '${tmp.path}/s.cdx.json';
    File(sbom).writeAsStringSync(jsonEncode({
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'components': [
        for (final (_, _, name, ver) in _matches)
          {
            'type': 'library',
            'name': name,
            'version': ver,
            'purl': 'pkg:generic/$name@$ver',
          },
      ],
    }));
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> scan(List<String> extra) => Process.run(
      'dart',
      [
        'run',
        'bin/sbom_generator.dart',
        '--lang',
        'en',
        'scan',
        '--sbom',
        sbom,
        '--no-enrich',
        ...extra,
      ],
      environment: env);

  Map<String, dynamic> parse(ProcessResult r) =>
      jsonDecode(r.stdout as String) as Map<String, dynamic>;

  test('--format json : résumé et résultats', () async {
    final r = await scan(['-f', 'json']);
    final j = parse(r);
    expect(j['schema'], 'sbom-generator/scan/v1');
    expect(j['summary']['total'], 3);
    expect(j['summary']['bySeverity'], {'Critical': 1, 'High': 1, 'Low': 1});
    expect((j['findings'] as List).first['scanner'], 'grype');
  });

  test('--ignore : règle active, règle expirée signalée', () async {
    final f = File('${tmp.path}/ignore.txt')
      ..writeAsStringSync('CVE-2024-0001; package=liba; reason=ok\n'
          'CVE-2024-0002; expires=2020-01-01; reason=vieux\n');
    final r = await scan(['-f', 'json', '--ignore', f.path]);
    final j = parse(r);
    expect(j['summary']['total'], 2);
    expect(j['summary']['ignored'], 1);
    expect(r.stderr, contains('EXPIRED'));
  });

  test('--vex OpenVEX : not_affected écarté et reporté dans --vex-out',
      () async {
    final vex = File('${tmp.path}/in.vex.json')
      ..writeAsStringSync(jsonEncode({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        'statements': [
          {
            'vulnerability': {'name': 'CVE-2024-0002'},
            'products': [
              {'@id': 'pkg:generic/libb@2.0'}
            ],
            'status': 'not_affected',
            'justification': 'component_not_present',
          },
        ],
      }));
    final out = '${tmp.path}/out.vex.json';
    final r = await scan(['-f', 'json', '--vex', vex.path, '--vex-out', out]);
    final j = parse(r);
    expect(j['summary']['vexSuppressed'], 1);
    expect((j['findings'] as List).map((f) => f['id']),
        isNot(contains('CVE-2024-0002')));
    final o = jsonDecode(File(out).readAsStringSync()) as Map;
    final st = o['statements'] as List;
    expect(st.where((s) => s['status'] == 'not_affected'), hasLength(1));
    final affected = st.firstWhere((s) =>
        s['status'] == 'affected' &&
        s['vulnerability']['name'] == 'CVE-2024-0001');
    expect(affected['products'].single['@id'], 'pkg:generic/liba@1.0');
    expect(affected['action_statement'], contains('9.9'));
  });

  test('--baseline : seules les nouvelles CVE restent ; code retour', () async {
    final base = File('${tmp.path}/base.json');
    final first = await scan(['-f', 'json']);
    base.writeAsStringSync(first.stdout as String);
    // Référence identique → plus rien, code 0.
    var r = await scan(['--baseline', base.path]);
    expect(r.exitCode, 0);
    // Référence amputée de la CVE critique → 1 nouvelle, code 1.
    final j = jsonDecode(base.readAsStringSync()) as Map<String, dynamic>;
    j['findings'] = (j['findings'] as List)
        .where((f) => f['id'] != 'CVE-2024-0001')
        .toList();
    base.writeAsStringSync(jsonEncode(j));
    r = await scan(['-f', 'json', '--baseline', base.path]);
    expect(r.exitCode, 1);
    expect(parse(r)['summary']['total'], 1);
  });

  test('--baseline invalide : erreur claire, code 1', () async {
    final f = File('${tmp.path}/bad.json')..writeAsStringSync('{"x":1}');
    final r = await scan(['--baseline', f.path]);
    expect(r.exitCode, 1);
    expect(r.stderr, contains('"findings" array missing'));
  });

  test('--fail-on : seuil de sévérité', () async {
    var r = await scan(['--fail-on', 'critical']);
    expect(r.exitCode, 1);
    final ign = File('${tmp.path}/i.txt')
      ..writeAsStringSync('CVE-2024-0001; reason=r\n');
    r = await scan(['--ignore', ign.path, '--fail-on', 'critical']);
    expect(r.exitCode, 0, reason: 'reste High et Low, sous le seuil');
    r = await scan(['--ignore', ign.path, '--fail-on', 'high']);
    expect(r.exitCode, 1);
  });

  test('--cache : le scanner n\'est lancé qu\'une fois', () async {
    final dir = '${tmp.path}/c';
    await scan(['-f', 'json', '--cache', '--cache-dir', dir]);
    final r = await scan(['-f', 'json', '--cache', '--cache-dir', dir]);
    expect(counter.readAsLinesSync().where((l) => l == 'run'), hasLength(1));
    expect(r.stderr, contains('read from the cache'));
    expect(parse(r)['summary']['total'], 3);
    // TTL 0 : le cache ne sert plus.
    await scan(
        ['-f', 'json', '--cache', '--cache-dir', dir, '--cache-ttl', '0']);
    expect(counter.readAsLinesSync().where((l) => l == 'run'), hasLength(2));
  });

  test('cra --ignore : la CVE ignorée disparaît de l\'inventaire', () async {
    Future<Map<String, dynamic>> cra(List<String> extra) async {
      final r = await Process.run(
          'dart',
          [
            'run',
            'bin/sbom_generator.dart',
            '--lang',
            'en',
            'cra',
            '-s',
            sbom,
            '--no-enrich',
            '-f',
            'json',
            ...extra,
          ],
          environment: env);
      return jsonDecode(r.stdout as String) as Map<String, dynamic>;
    }

    expect((await cra([]))['vulnerabilities']['total'], 3);
    final ign = File('${tmp.path}/i.txt')
      ..writeAsStringSync('CVE-2024-0001; reason=r\n');
    final v = (await cra(['--ignore', ign.path]))['vulnerabilities'];
    expect(v['total'], 2);
    expect(v['bySeverity']['critical'], 0);
  });
}
