import 'dart:convert';

import 'package:sbom_generator/report_input.dart';
import 'package:sbom_generator/scan_report_generator.dart';
import 'package:test/test.dart';

Map<String, dynamic> _f(String id, String sev, String pkg,
        {List<String> fixed = const [], String? extra}) =>
    {
      'id': id,
      'severity': sev,
      'package': pkg,
      'published': '2024-01-02T00:00:00Z',
      'modified': '2024-02-03T00:00:00Z',
      'fixedVersions': fixed,
      'fixState': fixed.isEmpty ? 'not-fixed' : 'fixed',
      if (extra != null) 'extra': extra,
    };

Map<String, dynamic> _scanJson({
  List<Map<String, dynamic>>? grype,
  List<Map<String, dynamic>>? trivy,
  Map<String, dynamic> exploit = const {},
  List<dynamic> vex = const [],
  String generatedAt = '2026-03-01T00:00:00Z',
}) =>
    {
      'schema': 'sbom-generator/scan/v1',
      'generatedAt': generatedAt,
      'target': 'x.cdx.json',
      'scanners': [if (grype != null) 'grype', if (trivy != null) 'trivy'],
      'toolVersions': {'sbom-generator': '1.8.0'},
      'exploit': exploit,
      if (vex.isNotEmpty) 'vex': vex,
      'findings': [
        for (final v in grype ?? const []) {'scanner': 'grype', ...v},
        for (final v in trivy ?? const []) {'scanner': 'trivy', ...v},
      ],
    };

ReportInput _in(Map<String, dynamic> j) => ReportInput.parse(j);

void main() {
  group('ReportInput', () {
    test('scan --format json : scanners exécutés (liste vide ≠ non exécuté)',
        () {
      final i = _in(_scanJson(grype: [], trivy: [_f('CVE-1', 'High', 'a@1')]));
      expect(i.results['grype'], isEmpty);
      expect(i.results['osv'], isNull);
      expect(i.results['trivy'], hasLength(1));
      expect(i.targets, ['x.cdx.json']);
      expect(i.generatedAt, DateTime.utc(2026, 3, 1));
    });

    test('exploitabilité : aller-retour exploitToJson / exploitFromJson', () {
      final i = _in(_scanJson(grype: [], exploit: {
        'CVE-1': {
          'kev': true,
          'kevAdded': '2022-01-01T00:00:00Z',
          'epss': 0.5,
          'poc': true,
          'pocUrls': ['https://x'],
        },
      }));
      final e = i.exploit['CVE-1']!;
      expect((e.inKev, e.epssScore, e.pocKnown), (true, 0.5, true));
      expect(exploitFromJson(exploitToJson(e)).pocUrls, ['https://x']);
    });

    test('session de la GUI : conversion, couches par clé, VEX', () {
      final i = _in({
        'format': 1,
        'savedAt': '2026-03-01T00:00:00Z',
        'guiVersion': '1.8.0',
        'targets': ['SBOM a.cdx.json'],
        'grype': [
          {
            'id': 'CVE-1',
            'severity': 'High',
            'package': 'libx',
            'version': '1.0',
            'fixed': '1.1',
            'type': 'rpm',
          },
          {
            'id': 'CVE-2',
            'severity': 'Low',
            'package': 'liby',
            'version': '2',
            'fixed': 'not-fixed',
            'type': 'rpm',
          },
        ],
        'layerScans': {
          'Grype': {
            'mode': 'attribute',
            'layers': [
              {'index': 1, 'digest': 'sha256:aaaaaaaaaaaaaaaa'},
              {
                'index': 2,
                'digest': 'sha256:bbbbbbbbbbbbbbbb',
                'createdBy': 'RUN x'
              },
            ],
            'byKey': {
              'CVE-1\u0000libx\u00001.0': [2],
            },
          },
        },
        'vex': [
          {
            'vulnId': 'CVE-2',
            'status': 'not_affected',
            'justification': 'component_not_present'
          },
        ],
      });
      final g = i.results['grype']!;
      expect(g[0]['package'], 'libx@1.0');
      expect(g[0]['fixedVersions'], ['1.1']);
      expect(g[0]['layer'], 2);
      expect(g[0]['extra'], 'rpm');
      expect(g[1]['fixedVersions'], isEmpty);
      expect(g[1]['fixState'], 'not-fixed');
      expect(g[1].containsKey('layer'), isFalse);
      expect(i.results['osv'], isNull);
      expect(i.layers.map((l) => l.index), [1, 2]);
      expect(i.layerScanMode, 'attribute');
      expect(i.vex.single.vulnId, 'CVE-2');
      expect(i.targets, ['SBOM a.cdx.json']);
    });

    test('fichier non reconnu : FormatException', () {
      expect(() => ReportInput.parse({'a': 1}), throwsFormatException);
    });
  });

  group('ScanReportGenerator.fromInput', () {
    final base = _in(_scanJson(
      grype: [
        _f('CVE-1', 'Critical', 'log4j@2.14',
            fixed: ['2.17.1'], extra: 'Remote code execution in a library'),
        _f('CVE-2', 'Medium', 'log4j@2.14', fixed: ['2.15.0']),
        _f('CVE-3', 'Low', 'zlib@1.0'),
      ],
      exploit: {
        'CVE-3': {'kev': true},
      },
    ));

    test('seuil : pire sévérité ou KEV, toutes les lignes d\'une CVE gardées',
        () {
      final g = ScanReportGenerator.fromInput(base, threshold: 'high');
      final ids = g.resultsByScanner['grype']!.map((v) => v['id']).toList();
      expect(ids, ['CVE-1', 'CVE-3'], reason: 'CVE-3 conservée car KEV');
      expect(g.uniqueBeforeThreshold, 3);
      final adoc = g.toAsciiDoc();
      expect(adoc, contains('rapport limité aux CVE de sévérité *≥ High*'));
      expect(adoc, contains('2 sur 3 CVE uniques'));
    });

    test('détail des CVE, remédiation et description', () {
      final adoc = ScanReportGenerator.fromInput(base).toAsciiDoc();
      expect(adoc, contains('== Détail des CVE'));
      expect(adoc, contains('=== CVE-1'));
      expect(adoc, contains('Remote code execution in a library'));
      expect(adoc, contains('https://nvd.nist.gov/vuln/detail/CVE-1'));
      expect(adoc, contains('== Remédiation'));
      expect(adoc, contains('`log4j`'));
      expect(adoc, contains('2.14 → *2.17.1*'));
    });

    test('VEX : CVE écartée, section dédiée, résumé', () {
      final withVex = _in(_scanJson(
        grype: [
          _f('CVE-1', 'Critical', 'a@1'),
          _f('CVE-2', 'High', 'b@1'),
        ],
        vex: [
          {
            'vulnId': 'CVE-1',
            'products': ['a@1'],
            'status': 'not_affected',
            'justification': 'component_not_present',
            'impact': 'absent',
          },
        ],
      ));
      final g = ScanReportGenerator.fromInput(withVex);
      expect(g.resultsByScanner['grype']!.map((v) => v['id']), ['CVE-2']);
      expect(g.vexSuppressed.single.id, 'CVE-1');
      final adoc = g.toAsciiDoc();
      expect(adoc, contains('== VEX'));
      expect(adoc, contains('1 CVE écartée(s) par une déclaration VEX'));
      expect(adoc, isNot(contains('=== CVE-1')));
      // applyVex: false : rien n'est écarté.
      final raw = ScanReportGenerator.fromInput(withVex, applyVex: false);
      expect(raw.resultsByScanner['grype'], hasLength(2));
      expect(raw.toAsciiDoc(), isNot(contains('== VEX')));
    });

    test('tendance : nouvelles, disparues, inchangées', () {
      final old = _in(_scanJson(
        grype: [
          _f('CVE-1', 'Critical', 'log4j@2.13'),
          _f('CVE-9', 'High', 'x@1')
        ],
        generatedAt: '2026-01-15T00:00:00Z',
      ));
      final g = ScanReportGenerator.fromInput(base, compareWith: old);
      final t = g.trend!;
      expect(t.added.keys, containsAll(['CVE-2|log4j', 'CVE-3|zlib']));
      expect(t.removed.keys, ['CVE-9|x']);
      expect(t.unchanged, 1,
          reason: 'CVE-1|log4j : la version n\'y compte pas');
      final adoc = g.toAsciiDoc();
      expect(adoc, contains('== Tendance'));
      expect(adoc, contains('du 2026-01-15'));
      expect(adoc, contains('CVE-9'));
    });

    test('Markdown : mêmes sections principales', () {
      final md = ScanReportGenerator.fromInput(base,
          compareWith: _in(_scanJson(grype: []))).toMarkdown();
      expect(md, contains('## Remédiation'));
      expect(md, contains('## Tendance'));
      expect(md, contains('## Détail des CVE'));
      expect(md, contains('### CVE-1'));
    });

    test('barre SVG de répartition dans la section par scanner', () {
      final adoc = ScanReportGenerator.fromInput(base).toAsciiDoc();
      final m = RegExp(r'image::data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)')
          .firstMatch(adoc);
      expect(m, isNotNull);
      expect(utf8.decode(base64.decode(m!.group(1)!)), contains('<svg'));
    });
  });
}
