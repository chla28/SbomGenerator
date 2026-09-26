import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/layer_scan.dart';
import 'package:sbom_generator/scan_report_generator.dart';
import 'package:test/test.dart';

const _d1 = 'sha256:1111111111111111111111111111111111111111111111111111111111111111';

Map<String, dynamic> _cdxComp(String name, String version, int layer) => {
      'name': name,
      'version': version,
      'properties': [
        {'name': 'sbom_generator:layer:index', 'value': '$layer'},
      ],
    };

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('layer_scan_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  void write(String name, Object json) =>
      File('${tmp.path}/$name').writeAsStringSync(jsonEncode(json));

  group('LayeredSbomSet.load', () {
    test('CycloneDX : composants, résumés de couche et fichiers', () {
      write('app.cdx.json', {
        'bomFormat': 'CycloneDX',
        'metadata': {
          'component': {
            'properties': [
              {'name': 'sbom_generator:layers:mode', 'value': 'rootfs'},
              {
                'name': 'sbom_generator:layers:001',
                'value': jsonEncode(
                    {'index': 1, 'digest': _d1, 'createdBy': 'ADD base'}),
              },
            ],
          },
        },
        'components': [
          _cdxComp('zlib', '1.3', 1),
          _cdxComp('curl', '8.0', 2),
        ],
      });
      write('app.layer-01-111111111111.cdx.json', {'bomFormat': 'CycloneDX'});
      write('app.layer-02-222222222222.cdx.json', {'bomFormat': 'CycloneDX'});
      write('app.layer-02-222222222222.spdx.json', {});

      final set = LayeredSbomSet.load('${tmp.path}/app.cdx.json')!;
      expect(set.mode, 'rootfs');
      expect(set.layers.map((l) => l.index), [1, 2]);
      expect(set.layers.first.createdBy, 'ADD base');
      expect(set.layers.first.shortDigest, '111111111111');
      expect(set.layers.last.digest, '222222222222'); // lu dans le nom
      expect(set.layers.last.path, endsWith('.layer-02-222222222222.cdx.json'));
      expect(set.layerOf('zlib@1.3'), 1);
      // Version normalisée par le scanner : repli sur le nom seul.
      expect(set.layerOf('curl@0:8.0'), 2);
      expect(set.layerOf('absent@1'), isNull);
    });

    test('SPDX 2.3 : annotations', () {
      write('app.spdx.json', {
        'spdxVersion': 'SPDX-2.3',
        'packages': [
          {
            'name': 'musl',
            'versionInfo': '1.2',
            'annotations': [
              {'comment': 'sbom_generator:layer:index=3; sbom_generator:layer:digest=x'},
            ],
          },
        ],
      });
      final set = LayeredSbomSet.load('${tmp.path}/app.spdx.json')!;
      expect(set.layerOf('musl@1.2'), 3);
    });

    test('SBOM sans couches : null', () {
      write('plain.cdx.json', {
        'bomFormat': 'CycloneDX',
        'components': [
          {'name': 'a', 'version': '1'},
        ],
      });
      expect(LayeredSbomSet.load('${tmp.path}/plain.cdx.json'), isNull);
    });

    test('nom ambigu entre couches : pas de repli sur le nom', () {
      write('app.cdx.json', {
        'bomFormat': 'CycloneDX',
        'components': [
          _cdxComp('lodash', '4.0', 1),
          _cdxComp('lodash', '3.0', 2),
        ],
      });
      final set = LayeredSbomSet.load('${tmp.path}/app.cdx.json')!;
      expect(set.layerOf('lodash@4.0'), 1);
      expect(set.layerOf('lodash@9.9'), isNull);
    });
  });

  test('attributeLayers et summarizeByLayer (dédoublonnage inter-scanners)',
      () {
    final set = LayeredSbomSet(
      globalPath: 'g',
      layerByPackage: {'zlib@1.3': 1, 'curl@8.0': 2},
      layers: const [
        LayerRef(index: 1, digest: _d1),
        LayerRef(index: 2, digest: 'sha256:22'),
      ],
    );
    final grype = <Map<String, dynamic>>[
      {'id': 'CVE-2026-0001', 'severity': 'High', 'package': 'zlib@1.3'},
      {'id': 'CVE-2026-0002', 'severity': 'Low', 'package': 'curl@8.0'},
      {'id': 'CVE-2026-0003', 'severity': 'Low', 'package': 'inconnu@1'},
    ];
    final osv = <Map<String, dynamic>>[
      {'id': 'DEBIAN-CVE-2026-0002', 'severity': 'Critical', 'package': 'curl@8.0'},
    ];
    expect(attributeLayers(grype, set), 1);
    attributeLayers(osv, set);
    expect(grype.first['layer'], 1);
    expect(grype.last.containsKey('layer'), isFalse);

    final s = summarizeByLayer({'grype': grype, 'osv': osv}, set.layers);
    expect(s.map((l) => l.total), [1, 1]);
    expect(s[1].count('critical'), 1); // pire sévérité entre scanners
    expect(s[1].count('low'), 0);
  });

  test('rapport : section « Couches » et colonne Couche(s)', () {
    final gen = ScanReportGenerator(
      sbomPath: 'image app.tar',
      resultsByScanner: {
        'grype': [
          {'id': 'CVE-2026-0001', 'severity': 'Critical', 'package': 'zlib@1', 'layer': 1},
        ],
        'trivy': [
          {'id': 'CVE-2026-0001', 'severity': 'High', 'package': 'zlib@1', 'layer': 1},
        ],
      },
      layers: const [
        LayerRef(index: 1, digest: _d1, createdBy: 'ADD base'),
        LayerRef(index: 2, digest: 'sha256:22', createdBy: 'RUN apk add'),
      ],
      layerScanMode: 'attribute',
    );
    final md = gen.toMarkdown();
    expect(md, contains('## Couches de l\'image'));
    expect(md, contains('| 1 | `111111111111` | ADD base | 1 | 1 | 0 |'));
    expect(md, contains('| 2 | `22` | RUN apk add | 0 | 0 | 0 |'));
    expect(md, contains('Couche(s) |'));
    final adoc = gen.toAsciiDoc();
    expect(adoc, contains('== Couches de l\'image'));
    expect(adoc, contains('| Trivy | Couche(s)'));

    final plain = ScanReportGenerator(
      sbomPath: 's',
      resultsByScanner: {'grype': const []},
    ).toMarkdown();
    expect(plain, isNot(contains('Couches de l')));
  });
}
