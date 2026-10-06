import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/remediation.dart';
import 'package:sbom_generator_gui/services/scan_enrichment.dart';

RemediationInput _r(
  String id,
  String sev,
  String pkg,
  String ver,
  String fix, {
  String scanner = 'Grype',
}) => (
  scanner: scanner,
  id: id,
  severity: sev,
  packageName: pkg,
  installedVersion: ver,
  fixedVersion: fix,
);

void main() {
  group('compareVersions', () {
    test('numérique, pas lexicographique', () {
      expect(compareVersions('2.9', '2.10'), lessThan(0));
      expect(compareVersions('2.17.1', '2.15.0'), greaterThan(0));
      expect(compareVersions('1.0', '1.0.0'), lessThan(0));
      expect(compareVersions('1.2.3', '1.2.3'), 0);
    });
    test('époque et suffixe de distribution ignorés', () {
      expect(compareVersions('1:2.0-3.el9', '2.0'), 0);
      expect(compareVersions('3.0.7-1.el9', '3.0.8'), lessThan(0));
    });
  });

  group('fixedVersionsOf', () {
    test('états de scanner = pas de correctif', () {
      expect(fixedVersionsOf('not-fixed'), isEmpty);
      expect(fixedVersionsOf('wont-fix'), isEmpty);
      expect(fixedVersionsOf(''), isEmpty);
      expect(fixedVersionsOf('unknown'), isEmpty);
    });
    test('une version ou une liste', () {
      expect(fixedVersionsOf('2.15.0'), ['2.15.0']);
      expect(fixedVersionsOf('2.12.2, 2.16.0'), ['2.12.2', '2.16.0']);
    });
  });

  group('buildRemediation', () {
    test(
      'un paquet : version cible = la plus haute des corrections minimales',
      () {
        final items = buildRemediation([
          _r('CVE-1', 'Critical', 'log4j-core', '2.14.1', '2.15.0'),
          _r('CVE-2', 'High', 'log4j-core', '2.14.1', '2.16.0'),
          _r('CVE-3', 'Medium', 'log4j-core', '2.14.1', '2.12.2, 2.17.1'),
        ]);
        expect(items, hasLength(1));
        final i = items.single;
        expect(
          i.targetVersion,
          '2.17.1',
        ); // CVE-3 : 2.12.2 < installée → 2.17.1
        expect(i.fixed.map((c) => c.id), ['CVE-1', 'CVE-2', 'CVE-3']);
        expect(i.unfixed, isEmpty);
        expect(i.worstFixedSeverity, 'critical');
      },
    );

    test('CVE sans correctif : restent, ne fixent pas la cible', () {
      final i = buildRemediation([
        _r('CVE-1', 'High', 'libx', '1.0', '1.1'),
        _r('CVE-2', 'Critical', 'libx', '1.0', 'not-fixed'),
      ]).single;
      expect(i.targetVersion, '1.1');
      expect(i.fixed.map((c) => c.id), ['CVE-1']);
      expect(i.unfixed.map((c) => c.id), ['CVE-2']);
      expect(i.remaining, greaterThan(i.gain));
    });

    test('paquet sans aucun correctif : cible nulle', () {
      final i = buildRemediation([
        _r('CVE-1', 'Low', 'a', '1', 'wont-fix'),
      ]).single;
      expect(i.targetVersion, isNull);
      expect(i.fixed, isEmpty);
    });

    test(
      'fusion inter-scanners et normalisation du préfixe de distribution',
      () {
        final i = buildRemediation([
          _r('CVE-2024-1', 'High', 'p', '1', '1.5', scanner: 'Grype'),
          _r(
            'DEBIAN-CVE-2024-1',
            'Medium',
            'p',
            '1',
            '1.5',
            scanner: 'OSV-Scanner',
          ),
        ]).single;
        expect(i.fixed, hasLength(1));
        expect(i.fixed.single.id, 'CVE-2024-1');
        expect(i.fixed.single.severity, 'high'); // la pire
        expect(i.fixed.single.scanners, {'Grype', 'OSV-Scanner'});
      },
    );

    test('tri par gain de risque ; KEV pèse plus que la sévérité', () {
      final items = buildRemediation(
        [
          _r('CVE-A', 'Critical', 'gros', '1', '2'),
          _r('CVE-B', 'Low', 'kev', '1', '2'),
        ],
        exploitById: {'CVE-B': const ExploitInfo(inKev: true, epssScore: 0.9)},
      );
      expect(items.first.packageName, 'kev');
      expect(items.first.kevFixed, 1);
    });

    test('versions installées distinctes du même paquet : deux entrées', () {
      final items = buildRemediation([
        _r('CVE-1', 'High', 'p', '1.0', '1.1'),
        _r('CVE-1', 'High', 'p', '2.0', '2.1'),
      ]);
      expect(items.map((i) => i.targetVersion).toSet(), {'1.1', '2.1'});
    });
  });
}
