/// Integration test for `sbom_generator scan` CVE enrichment (exploitability /
/// active exploitation): the KEV / EPSS / PoC columns, `--only-kev`,
/// `--epss-min` and `--sort risk`.
///
/// Runs with `--no-enrich` so no network request is made — the signals come
/// from Grype's own database (which ships CISA KEV + EPSS). Skipped when
/// `grype` is absent or its DB cannot be reached.
@TestOn('posix')
library;

import 'dart:io';
import 'package:test/test.dart';

Future<bool> _hasGrype() async {
  try {
    final r = await Process.run('grype', ['version']);
    return r.exitCode == 0;
  } on ProcessException {
    return false;
  }
}

const _sbom = '''
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "group": "org.apache.logging.log4j",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    }
  ]
}
''';

void main() {
  late bool hasGrype;
  late Directory tmp;

  setUpAll(() async => hasGrype = await _hasGrype());
  setUp(() => tmp = Directory.systemTemp.createTempSync('scan_enrich_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> runScan(List<String> extra) {
    final sbom = File('${tmp.path}/sbom.cdx.json')..writeAsStringSync(_sbom);
    return Process.run(
      'dart',
      [
        'run',
        'bin/sbom_generator.dart',
        '--lang',
        'fr',
        'scan',
        '--sbom',
        sbom.path,
        '--scanner',
        'grype',
        '--no-enrich',
        ...extra
      ],
      environment: {'NO_COLOR': '1'},
    );
  }

  test('--only-kev ne garde que CVE-2021-44228 & consorts (KEV via Grype)',
      () async {
    if (!hasGrype) {
      markTestSkipped('grype absent — test d\'intégration ignoré');
      return;
    }
    final r = await runScan(['--only-kev', '--sort', 'risk']);
    expect(r.exitCode, 1, reason: 'des CVE KEV sont trouvées');
    final out = r.stdout as String;
    expect(out, contains('CVE-2021-44228'));
    expect(out, contains('KEV'));
    // log4shell est au catalogue KEV : colonne cochée.
    final line = out
        .split('\n')
        .firstWhere((l) => l.contains('CVE-2021-44228'), orElse: () => '');
    expect(line, contains('✓'));
    // Une CVE log4j non-KEV (ex. CVE-2021-44832) est filtrée.
    expect(out, isNot(contains('CVE-2021-44832')));
  });

  test('--epss-min filtre sur le score EPSS fourni par Grype', () async {
    if (!hasGrype) {
      markTestSkipped('grype absent — test d\'intégration ignoré');
      return;
    }
    final high = await runScan(['--epss-min', '0.9']);
    final low = await runScan(['--epss-min', '0.0']);
    final nHigh = RegExp(r'CVE-\d{4}-\d+')
        .allMatches(high.stdout as String)
        .map((m) => m.group(0))
        .toSet()
        .length;
    final nLow = RegExp(r'CVE-\d{4}-\d+')
        .allMatches(low.stdout as String)
        .map((m) => m.group(0))
        .toSet()
        .length;
    expect(nHigh, lessThan(nLow));
    expect((high.stdout as String), contains('CVE-2021-44228'));
  });
}
