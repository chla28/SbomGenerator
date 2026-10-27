/// `offline` : export / import / status du cache d'enrichissement.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('offline_it_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> offline(List<String> args) => Process.run('dart',
      ['run', 'bin/sbom_generator.dart', '--lang', 'fr', 'offline', ...args]);

  test('export, import dans un autre cache, status', () async {
    final src = Directory('${tmp.path}/src')..createSync();
    File('${src.path}/kev.json').writeAsStringSync(jsonEncode({
      'fetchedAt': '2026-01-01T00:00:00Z',
      'cves': {'CVE-2024-0001': {}},
    }));
    final bundle = '${tmp.path}/o.json.gz';

    var r = await offline(['export', '--cache-dir', src.path, '-o', bundle]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(File(bundle).existsSync(), isTrue);

    final dst = '${tmp.path}/dst';
    r = await offline(['import', '--cache-dir', dst, bundle]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(r.stdout, contains('kev.json'));

    r = await offline(['status', '--cache-dir', dst]);
    expect(r.exitCode, 0);
    expect(r.stdout, contains('kev.json  1'));
  });

  test('cache vide : export refusé ; bundle illisible : code 1', () async {
    var r = await offline([
      'export',
      '--cache-dir',
      '${tmp.path}/vide',
      '-o',
      '${tmp.path}/x.gz'
    ]);
    expect(r.exitCode, 1);
    expect(r.stderr, contains('cache vide'));
    File('${tmp.path}/junk').writeAsStringSync('non');
    r = await offline(
        ['import', '--cache-dir', '${tmp.path}/d', '${tmp.path}/junk']);
    expect(r.exitCode, 1);
    expect(r.stderr, contains('illisible'));
  });

  test('action inconnue ou absente : code 1', () async {
    expect((await offline(['bidule'])).exitCode, 1);
    expect((await offline([])).exitCode, 1);
  });
}
