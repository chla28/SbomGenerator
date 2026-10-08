import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/layer_scan.dart';
import 'package:sbom_generator_gui/models/scan_session.dart';
import 'package:sbom_generator_gui/models/vex.dart';
import 'package:sbom_generator_gui/services/scan_enrichment.dart';
import 'package:sbom_generator_gui/services/session_store.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/osv_panel.dart';
import 'package:sbom_generator_gui/widgets/trivy_panel.dart';

GrypeVuln _g(String id, String sev, {String pkg = 'p', String ver = '1.0'}) =>
    GrypeVuln(
      id: id,
      severity: sev,
      packageName: pkg,
      installedVersion: ver,
      fixedVersion: '1.1',
      packageType: 'rpm',
      publishedDate: DateTime.utc(2024, 1, 2),
    );

ScanSession _session(
  DateTime at, {
  List<GrypeVuln>? grype,
  List<OsvVuln>? osv,
  List<TrivyVuln>? trivy,
  List<String> targets = const ['SBOM a.cdx.json'],
}) => ScanSession(
  savedAt: at,
  guiVersion: '1.7.0',
  targets: targets,
  grype: grype,
  osv: osv,
  trivy: trivy,
  exploit: {
    'CVE-1': ExploitInfo(
      inKev: true,
      epssScore: 0.5,
      kevDueDate: DateTime.utc(2025, 1, 1),
      pocUrls: const ['https://x'],
      pocKnown: true,
      pocCount: 1,
    ),
  },
);

void main() {
  group('ScanSession', () {
    test(
      'aller-retour JSON : vulnérabilités, null conservé, exploitabilité',
      () {
        final s = _session(
          DateTime.utc(2026, 1, 1),
          grype: [_g('CVE-1', 'Critical')],
          osv: [
            const OsvVuln(
              id: 'GHSA-x',
              severity: 'HIGH',
              packageName: 'q',
              installedVersion: '2',
              fixedVersion: '3',
              ecosystem: 'npm',
              occurrenceCount: 2,
            ),
          ],
        );
        final back = ScanSession.decode(s.encode());
        expect(back.grype!.single.id, 'CVE-1');
        expect(back.grype!.single.publishedDate, DateTime.utc(2024, 1, 2));
        expect(back.osv!.single.occurrenceCount, 2);
        expect(back.osv!.single.ecosystem, 'npm');
        expect(back.trivy, isNull, reason: 'scanner non exécuté ≠ vide');
        expect(back.exploit['CVE-1']!.inKev, isTrue);
        expect(back.exploit['CVE-1']!.epssScore, 0.5);
        expect(back.exploit['CVE-1']!.pocUrls, ['https://x']);
        expect(back.targets, ['SBOM a.cdx.json']);
      },
    );

    test('couches et VEX : aller-retour JSON, clé lue par le CLI', () {
      final key = vulnLayerKey('CVE-1', 'p', '1.0');
      final s0 = ScanSession(
        savedAt: DateTime.utc(2026, 1, 1),
        guiVersion: '1.8.0',
        grype: [_g('CVE-1', 'High')],
        layerScans: {
          'Grype': LayerScanResult(
            mode: LayerScanMode.each,
            layers: const [
              LayerInfo(index: 1, digest: 'sha256:aa', createdBy: 'RUN x'),
              LayerInfo(index: 2, digest: 'sha256:bb'),
            ],
            layersByKey: {
              key: {2, 1},
            },
            unattributed: 3,
          ),
        },
        vex: const [
          VexStatement(
            vulnId: 'CVE-1',
            products: ['p@1.0'],
            status: 'not_affected',
            justification: 'component_not_present',
            impactStatement: 'absent',
          ),
        ],
      );
      final json = s0.toJson();
      // Contrat avec `sbom-generator report` (lib/report_input.dart du CLI).
      expect(json['layerScans']['Grype']['byKey']['CVE-1\u0000p\u00001.0'], [
        1,
        2,
      ]);
      expect(json['layerScans']['Grype']['mode'], 'each');
      expect(json['vex'][0]['impact'], 'absent');

      final back = ScanSession.decode(s0.encode());
      final ls = back.layerScans['Grype']!;
      expect(ls.mode, LayerScanMode.each);
      expect(ls.layers.map((l) => l.index), [1, 2]);
      expect(ls.layers.first.createdBy, 'RUN x');
      expect(ls.layersOf('CVE-1', 'p', '1.0'), [1, 2]);
      expect(ls.unattributed, 3);
      expect(back.vex.single.justification, 'component_not_present');
      expect(back.vex.single.products, ['p@1.0']);
    });

    test('session sans couches ni VEX : clés absentes', () {
      final j = _session(DateTime.utc(2026, 1, 1), grype: []).toJson();
      expect(j.containsKey('layerScans'), isFalse);
      expect(j.containsKey('vex'), isFalse);
    });

    test('format inconnu ou JSON invalide : FormatException', () {
      expect(
        () => ScanSession.fromJson({'format': 99, 'savedAt': 'x'}),
        throwsFormatException,
      );
      expect(() => ScanSession.decode('[]'), throwsA(isA<Object>()));
    });

    test('CVE uniques : id normalisé, tous scanners confondus', () {
      final s = _session(
        DateTime.utc(2026, 1, 1),
        grype: [_g('CVE-2024-1', 'High')],
        osv: [
          const OsvVuln(
            id: 'DEBIAN-CVE-2024-1',
            severity: 'MEDIUM',
            packageName: 'p',
            installedVersion: '1.0',
            fixedVersion: '',
            ecosystem: 'Debian',
          ),
        ],
      );
      expect(s.uniqueCveCount, 1);
      expect(s.findings().values.single, 'high', reason: 'la pire sévérité');
    });
  });

  group('SessionTrend', () {
    test('nouvelles, corrigées, inchangées, totaux par sévérité', () {
      final before = _session(
        DateTime.utc(2026, 1, 1),
        grype: [_g('CVE-1', 'High'), _g('CVE-2', 'Low'), _g('CVE-3', 'Medium')],
      );
      final after = _session(
        DateTime.utc(2026, 2, 1),
        grype: [_g('CVE-1', 'High'), _g('CVE-4', 'Critical')],
      );
      final t = SessionTrend.compare(before, after);
      expect(t.added.keys.map(SessionTrend.idOf), ['CVE-4']);
      expect(t.removed.keys.map(SessionTrend.idOf).toSet(), {'CVE-2', 'CVE-3'});
      expect(t.unchanged, 1);
      expect(t.beforeTotal, 3);
      expect(t.afterTotal, 2);
      expect(t.afterBySeverity['critical'], 1);
      expect(SessionTrend.packageOf(t.added.keys.single), 'p');
    });
  });

  group('SessionStore', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('sessions_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    test(
      'même cible le même jour : une seule entrée ; autre cible : deux',
      () async {
        final store = SessionStore(Directory('${tmp.path}/h'));
        final a1 = _session(
          DateTime(2026, 3, 1, 9),
          grype: [_g('CVE-1', 'High')],
        );
        final a2 = _session(
          DateTime(2026, 3, 1, 17),
          grype: [_g('CVE-2', 'High')],
        );
        final b = _session(
          DateTime(2026, 3, 1, 10),
          targets: const ['image nginx'],
          grype: [_g('CVE-9', 'Low')],
        );
        await store.save(a1);
        await store.save(a2);
        await store.save(b);
        final list = await store.list();
        expect(list, hasLength(2));
        expect(list.first.session.targets, [
          'SBOM a.cdx.json',
        ], reason: 'la plus récente (17 h)');
        expect(list.first.session.grype!.single.id, 'CVE-2');
      },
    );

    test(
      'fichiers illisibles ignorés ; suppression ; purge au-delà du maximum',
      () async {
        final dir = Directory('${tmp.path}/h')..createSync();
        File('${dir.path}/casse.json').writeAsStringSync('{pas du json');
        final store = SessionStore(dir, maxEntries: 2);
        for (var d = 1; d <= 4; d++) {
          await store.save(
            _session(
              DateTime(2026, 3, d),
              targets: ['t$d'],
              grype: [_g('CVE-$d', 'Low')],
            ),
          );
        }
        final list = await store.list();
        expect(list.map((e) => e.session.targets.single), ['t4', 't3']);
        await store.delete(list.first.file);
        expect(await store.list(), hasLength(1));
        await store.clear();
        expect(await store.list(), isEmpty);
      },
    );
  });
}
