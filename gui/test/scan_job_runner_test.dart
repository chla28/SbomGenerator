import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/services/scan_job_runner.dart';
import 'package:sbom_generator_gui/services/scan_queue.dart';

bool _has(String tool) => Process.runSync('which', [tool]).exitCode == 0;

void main() {
  test(
    'exécuteur réel : Grype sur un SBOM, résultat remis au tableau de bord',
    () async {
      final tmp = Directory.systemTemp.createTempSync('jobrun_');
      addTearDown(() => tmp.deleteSync(recursive: true));
      final sbom = File('${tmp.path}/v.cdx.json')
        ..writeAsStringSync(
          jsonEncode({
            'bomFormat': 'CycloneDX',
            'specVersion': '1.6',
            'components': [
              {
                'type': 'library',
                'name': 'log4j-core',
                'version': '2.14.1',
                'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
              },
            ],
          }),
        );
      ScanJobResult? got;
      final queue = ScanQueue(
        makeScanJobExecutor(
          onResult: (r) => got = r,
          enrichOnline: () async => false,
        ),
      );
      final job = queue.add('Grype', sbom.path);
      await queue.waitIdle();
      expect(job.error, isNull);
      expect(job.status, ScanJobStatus.done);
      expect(job.findings, greaterThan(0));
      expect(got!.scanner, 'Grype');
      expect(got!.target, 'SBOM v.cdx.json');
      expect(got!.grype!.any((v) => v.id == 'CVE-2021-44228'), isTrue);
      queue.dispose();
    },
    skip: _has('grype') ? false : 'grype absent',
    timeout: const Timeout(Duration(minutes: 3)),
  );

  test('scanner inconnu : échec explicite, pas d\'exception', () async {
    final tmp = Directory.systemTemp.createTempSync('jobrun_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final sbom = File('${tmp.path}/v.cdx.json')..writeAsStringSync('{}');
    final queue = ScanQueue(
      makeScanJobExecutor(onResult: (_) {}, enrichOnline: () async => false),
    );
    final job = queue.add('Inconnu', sbom.path);
    await queue.waitIdle();
    expect(job.status, ScanJobStatus.failed);
    queue.dispose();
  });
}
