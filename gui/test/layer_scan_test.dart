import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/layer_scan.dart';
import 'package:sbom_generator_gui/services/layer_scan_service.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

const _d1 =
    'sha256:1111111111111111111111111111111111111111111111111111111111111111';
const _d2 =
    'sha256:2222222222222222222222222222222222222222222222222222222222222222';

String _grype(List<(String, String, String)> matches) => jsonEncode({
  'matches': [
    for (final (id, name, ver) in matches)
      {
        'vulnerability': {'id': id, 'severity': 'High'},
        'artifact': {'name': name, 'version': ver, 'type': 'apk'},
      },
  ],
});

LayeredSbomSet _set() => LayeredSbomSet(
  globalPath: '/x/img.cdx.json',
  layerByPackage: const {'zlib@1.3': 1, 'curl@8.0': 2},
  layers: const [
    LayerInfo(index: 1, digest: _d1, createdBy: 'ADD base', path: '/x/l1'),
    LayerInfo(index: 2, digest: _d2, createdBy: 'RUN apk add', path: '/x/l2'),
  ],
);

void main() {
  group('LayeredSbomSet', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('gui_layer_scan_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    test('parse : composants, résumés et fichiers de couche', () {
      final global = '${tmp.path}/img.cdx.json';
      File(global).writeAsStringSync('{}');
      File(
        '${tmp.path}/img.layer-01-111111111111.cdx.json',
      ).writeAsStringSync('{}');
      File(
        '${tmp.path}/img.layer-02-222222222222.cdx.json',
      ).writeAsStringSync('{}');
      final set = LayeredSbomSet.parse(global, {
        'bomFormat': 'CycloneDX',
        'metadata': {
          'component': {
            'properties': [
              {
                'name': 'sbom_generator:layers:001',
                'value': jsonEncode({
                  'index': 1,
                  'digest': _d1,
                  'createdBy': 'ADD base',
                }),
              },
            ],
          },
        },
        'components': [
          {
            'name': 'zlib',
            'version': '1.3',
            'properties': [
              {'name': 'sbom_generator:layer:index', 'value': '1'},
            ],
          },
        ],
      });
      expect(set.layers.map((l) => l.index), [1, 2]);
      expect(set.layers.first.createdBy, 'ADD base');
      expect(set.layers.last.path, endsWith('.layer-02-222222222222.cdx.json'));
      expect(set.layerOf('zlib', '1.3'), 1);
      expect(set.layerOf('zlib', '1.3-r0'), 1); // repli sur le nom
      expect(set.layerOfDigest(_d1), 1);
      expect(set.layerOfDigest(_d2), 2); // digest court lu dans le nom
    });
  });

  test('fusion des sorties et couches natives trivy', () {
    final merged =
        jsonDecode(
              mergeGrypeJson([
                _grype([('CVE-1', 'zlib', '1.3')]),
                _grype([('CVE-2', 'curl', '8.0')]),
              ]),
            )
            as Map;
    expect((merged['matches'] as List), hasLength(2));
    expect(
      (jsonDecode(mergeTrivyJson(['{"Results":[1]}', '{"Results":[2]}']))
          as Map)['Results'],
      [1, 2],
    );
    expect((jsonDecode(mergeOsvJson(['{"results":[1]}'])) as Map)['results'], [
      1,
    ]);
    final native = trivyLayerDigests(
      jsonEncode({
        'Results': [
          {
            'Vulnerabilities': [
              {
                'VulnerabilityID': 'CVE-1',
                'PkgName': 'zlib',
                'InstalledVersion': '1.3',
                'Layer': {'DiffID': _d2},
              },
            ],
          },
        ],
      }),
    );
    expect(native[vulnLayerKey('CVE-1', 'zlib', '1.3')], _d2);

    final osv = osvLayerDigests(
      jsonEncode({
        'image_metadata': {
          'layer_metadata': [
            {'diff_id': _d1},
            {'diff_id': ''},
            {'diff_id': _d2},
          ],
        },
        'results': [
          {
            'packages': [
              {
                'package': {
                  'name': 'expat',
                  'version': '2.8',
                  'image_origin_details': {'index': 2},
                },
                'vulnerabilities': [
                  {
                    'id': 'ALPINE-CVE-2026-1',
                    'aliases': ['CVE-2026-1'],
                  },
                ],
              },
            ],
          },
        ],
      }),
    );
    expect(osv[vulnLayerKey('CVE-2026-1', 'expat', '2.8')], _d2);
  });

  group('LayerScanService.run', () {
    test('rattachement : un scan de l\'image, couche du paquet', () async {
      final targets = <String>[];
      final r = await LayerScanService.run(
        image: 'img.tar',
        settings: const LayerScanSettings(enabled: true),
        prepareSet: (_, _) async => _set(),
        scanOnce: (t, useImage) async {
          targets.add('$t:$useImage');
          return (
            json: _grype([
              ('CVE-1', 'zlib', '1.3'),
              ('CVE-2', 'curl', '8.0'),
              ('CVE-3', 'absent', '1'),
            ]),
            exitCode: 0,
            stderr: null,
          );
        },
        parse: GrypeVuln.fromJson,
        merge: mergeGrypeJson,
      );
      expect(targets, ['img.tar:true']);
      expect(r.layerScan.mode, LayerScanMode.attribute);
      expect(r.layerScan.label('CVE-1', 'zlib', '1.3'), '1');
      expect(r.layerScan.label('CVE-2', 'curl', '8.0'), '2');
      expect(r.layerScan.label('CVE-3', 'absent', '1'), '?');
      expect(r.layerScan.unattributed, 1);
    });

    test('rattachement : couche native prioritaire', () async {
      final r = await LayerScanService.run(
        image: 'img.tar',
        settings: const LayerScanSettings(enabled: true),
        prepareSet: (_, _) async => _set(),
        scanOnce: (_, _) async => (
          json: _grype([('CVE-1', 'zlib', '1.3')]),
          exitCode: 0,
          stderr: null,
        ),
        parse: GrypeVuln.fromJson,
        merge: mergeGrypeJson,
        nativeDigests: (_) => {vulnLayerKey('CVE-1', 'zlib', '1.3'): _d2},
      );
      expect(r.layerScan.label('CVE-1', 'zlib', '1.3'), '2');
    });

    test(
      'chaque couche : un scan par SBOM de couche, sorties fusionnées',
      () async {
        final targets = <String>[];
        final r = await LayerScanService.run(
          image: 'img.tar',
          settings: const LayerScanSettings(
            enabled: true,
            mode: LayerScanMode.each,
          ),
          prepareSet: (_, _) async => _set(),
          scanOnce: (t, useImage) async {
            targets.add('$t:$useImage');
            return (
              json: t == '/x/l1'
                  ? _grype([('CVE-1', 'zlib', '1.2')])
                  : _grype([
                      ('CVE-1', 'zlib', '1.2'),
                      ('CVE-2', 'curl', '8.0'),
                    ]),
              exitCode: 1,
              stderr: null,
            );
          },
          parse: GrypeVuln.fromJson,
          merge: mergeGrypeJson,
        );
        expect(targets, ['/x/l1:false', '/x/l2:false']);
        expect(r.exitCode, 1);
        expect(GrypeVuln.fromJson(r.json), hasLength(3));
        expect(r.layerScan.label('CVE-1', 'zlib', '1.2'), '1, 2');
        expect(r.layerScan.label('CVE-2', 'curl', '8.0'), '2');
      },
    );
  });

  testWidgets('VulnTableView : colonne, filtre et regroupement par couche', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final vulns = GrypeVuln.fromJson(
      _grype([
        ('CVE-2026-0001', 'zlib', '1.3'),
        ('CVE-2026-0002', 'curl', '8.0'),
      ]),
    );
    final scan = LayerScanResult(
      mode: LayerScanMode.attribute,
      layers: _set().layers,
      layersByKey: {
        vulnLayerKey('CVE-2026-0001', 'zlib', '1.3'): {1},
        vulnLayerKey('CVE-2026-0002', 'curl', '8.0'): {2},
      },
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: VulnTableView<GrypeVuln>(
            vulns: vulns,
            parseFailedMessage: '',
            severityOrder: const ['High'],
            toolName: 'Grype',
            csvDialogTitle: '',
            csvFileName: 'g.csv',
            csvHeader: 'Sévérité,CVE',
            csvRow: (v) => [v.severity, v.id],
            layerScan: scan,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('COUCHE'), findsOneWidget);
    expect(find.text('CVE-2026-0001'), findsOneWidget);
    expect(find.text('CVE-2026-0002'), findsOneWidget);

    // Filtre sur la couche 2.
    await tester.tap(find.text('Toutes les couches').first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Couche 2 (1)').last);
    await tester.pumpAndSettle();
    expect(find.text('CVE-2026-0001'), findsNothing);
    expect(find.text('CVE-2026-0002'), findsOneWidget);

    // Retour à toutes les couches, puis regroupement.
    await tester.tap(find.text('Couche 2 (1)').first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Toutes les couches').last);
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Grouper par couche'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Couche 1 ('), findsOneWidget);
    expect(find.text('ADD base'), findsOneWidget);
    expect(find.text('RUN apk add'), findsOneWidget);
  });
}
