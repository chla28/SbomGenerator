import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/services/scan_enrichment.dart';
import 'package:sbom_generator_gui/widgets/cve_detail.dart';

void main() {
  final detail = CveDetail(
    id: 'CVE-2021-44228',
    views: const [
      ScannerCveView(
        scanner: 'Grype',
        severity: 'Critical',
        packageName: 'log4j-core',
        installedVersion: '2.14.1',
        fixedVersion: '2.15.0',
        extra: 'java-archive',
      ),
      ScannerCveView(
        scanner: 'Trivy',
        severity: 'CRITICAL',
        packageName: 'log4j-core',
        installedVersion: '2.14.1',
        fixedVersion: '2.15.0',
        extra: 'Apache Log4j2 JNDI features do not protect against attacker '
            'controlled LDAP',
      ),
    ],
    exploit: ExploitInfo(
      inKev: true,
      kevDateAdded: DateTime(2021, 12, 10),
      kevDueDate: DateTime(2021, 12, 24),
      kevRansomware: true,
      epssScore: 0.97,
      epssPercentile: 0.999,
      pocKnown: true,
      pocCount: 12,
      pocUrls: const ['https://github.com/x/poc'],
      cvssBaseScore: 10.0,
      cvssExploitabilityScore: 3.9,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      exploitMaturity: 'High',
    ),
  );

  group('CveDetail', () {
    test('description : garde la phrase, écarte les champs courts', () {
      expect(detail.description, contains('Apache Log4j2'));
      expect(detail.description, isNot(contains('java-archive')));
    });

    test('links : NVD + CVE.org + osv.dev + CISA KEV pour une CVE KEV', () {
      final labels = detail.links.map((l) => l.$1).toList();
      expect(labels, containsAll(['NVD', 'CVE.org', 'osv.dev', 'CISA KEV']));
      expect(detail.links.firstWhere((l) => l.$1 == 'NVD').$2,
          'https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
    });

    test('links : GHSA → GitHub Advisory, pas de NVD/KEV', () {
      const d = CveDetail(id: 'GHSA-jfh8-c2jp-5v3q', views: []);
      final labels = d.links.map((l) => l.$1).toList();
      expect(labels, contains('GitHub Advisory'));
      expect(labels, isNot(contains('NVD')));
      expect(labels, isNot(contains('CISA KEV')));
    });

    test('toAdocRows : reprend paquet, KEV, EPSS, CVSS, PoC, liens', () {
      final adoc = detail.toAdocRows((s) => s);
      expect(adoc, contains('| Paquet | `log4j-core 2.14.1 → 2.15.0`'));
      expect(adoc,
          contains('| Rapporté par | Grype (CRITIQUE), Trivy (CRITIQUE)'));
      expect(adoc, contains('| CISA KEV | Oui'));
      expect(adoc, contains('échéance 2021-12-24'));
      expect(adoc, contains('rançongiciel'));
      expect(adoc, contains('| EPSS | 0.97 (percentile p100)'));
      expect(adoc, contains('exploitabilité 3.9/3.9'));
      expect(adoc, contains('maturité High'));
      expect(adoc, contains('| PoC public | 12 dépôt(s)'));
      expect(adoc, contains('nvd.nist.gov'));
    });
  });

  group('CveDetailPanel', () {
    testWidgets('affiche paquet, sévérité par scanner et signaux KEV/EPSS',
        (tester) async {
      tester.view.physicalSize = const Size(1000, 1200);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(child: CveDetailPanel(detail: detail)),
        ),
      ));
      await tester.pumpAndSettle();

      expect(find.textContaining('log4j-core 2.14.1'), findsWidgets);
      expect(find.textContaining('exploitée activement dans la nature'),
          findsOneWidget);
      expect(find.textContaining('EPSS 0.97'), findsOneWidget);
      expect(find.textContaining('12 dépôt(s)'), findsOneWidget);
      expect(find.text('NVD'), findsOneWidget);
      expect(find.text('CISA KEV'), findsOneWidget); // bouton lien
    });

    testWidgets('sans signal d\'exploitation : message dédié', (tester) async {
      addTearDown(tester.view.reset);
      const bare = CveDetail(
        id: 'CVE-2020-0001',
        views: [
          ScannerCveView(
            scanner: 'OSV-Scanner',
            severity: 'Medium',
            packageName: 'foo',
            installedVersion: '1.0',
            fixedVersion: '',
            extra: 'npm',
          ),
        ],
      );
      await tester.pumpWidget(const MaterialApp(
        home: Scaffold(body: CveDetailPanel(detail: bare)),
      ));
      await tester.pumpAndSettle();
      expect(find.text('Aucun signal d\'exploitation connu.'), findsOneWidget);
    });
  });
}
