import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/services/scan_enrichment.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

const _severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Negligible'];

Widget _table(
  List<GrypeVuln> vulns, {
  Map<String, ExploitInfo> exploitById = const {},
}) =>
    MaterialApp(
      home: Scaffold(
        body: VulnTableView<GrypeVuln>(
          vulns: vulns,
          parseFailedMessage: 'x',
          severityOrder: _severityOrder,
          toolName: 'Grype',
          csvDialogTitle: 'x',
          csvFileName: 'grype_vulns.csv',
          csvHeader:
              'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Type',
          csvRow: (v) => [
            v.severity,
            v.id,
            v.packageName,
            v.installedVersion,
            v.fixedVersion,
            v.packageType,
          ],
          extraColumnHeader: 'TYPE',
          extraOf: (v) => v.packageType,
          exploitById: exploitById,
        ),
      ),
    );

void main() {
  test('adocEscape échappe le caractère "|" (ambigu en tête de cellule AsciiDoc)', () {
    expect(adocEscape('foo|bar'), 'foo\\|bar');
    expect(adocEscape('sans pipe'), 'sans pipe');
  });

  testWidgets(
      'le bouton "Exporter en AsciiDoc + PDF" est actif dès qu\'une vulnérabilité est affichée',
      (tester) async {
    // Taille "desktop" réaliste : à la taille par défaut des tests (800x600),
    // la barre d'outils déborde (comportement déjà connu, cf.
    // config_panel_input_test.dart / sbom_merge_panel_test.dart).
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(_table(const [
      GrypeVuln(
        id: 'CVE-2024-0001',
        severity: 'Critical',
        packageName: 'openssl',
        installedVersion: '3.0.1',
        fixedVersion: '3.0.9',
        packageType: 'rpm',
      ),
    ]));
    await tester.pumpAndSettle();

    final button = tester.widget<IconButton>(
        find.widgetWithIcon(IconButton, Icons.picture_as_pdf_outlined));
    expect(button.onPressed, isNotNull);
  });

  testWidgets(
      'aucune barre d\'outils (donc aucun bouton d\'export) sans vulnérabilité',
      (tester) async {
    await tester.pumpWidget(_table(const []));
    await tester.pumpAndSettle();

    expect(find.byIcon(Icons.picture_as_pdf_outlined), findsNothing);
    expect(find.byIcon(Icons.download_outlined), findsNothing);
  });

  group('dedupeVulns', () {
    const sample = GrypeVuln(
      id: 'CVE-2026-54513',
      severity: 'Critical',
      packageName: 'jackson-databind',
      installedVersion: '2.17.2.redhat-00004',
      fixedVersion: '',
      packageType: 'java-archive',
    );

    test(
        'fusionne les entrées partageant sévérité/id/paquet/version '
        '(même bibliothèque détectée à plusieurs emplacements de l\'image)',
        () {
      final result = dedupeVulns<GrypeVuln>(
        [sample, sample],
        (v, n) => v.withOccurrenceCount(n),
      );

      expect(result, hasLength(1));
      expect(result.single.occurrenceCount, 2);
      expect(result.single.id, sample.id);
    });

    test('ne fusionne pas des entrées dont un des 4 champs clés diffère', () {
      final autre = sample.withOccurrenceCount(1); // même clé, count=1 explicite
      final versionDifferente = GrypeVuln(
        id: sample.id,
        severity: sample.severity,
        packageName: sample.packageName,
        installedVersion: '2.17.2.redhat-00005', // diffère
        fixedVersion: '',
        packageType: 'java-archive',
      );

      final result = dedupeVulns<GrypeVuln>(
        [autre, versionDifferente],
        (v, n) => v.withOccurrenceCount(n),
      );

      expect(result, hasLength(2));
      expect(result.every((v) => v.occurrenceCount == 1), isTrue);
    });

    test('préserve l\'ordre de première apparition', () {
      const high = GrypeVuln(
        id: 'CVE-1',
        severity: 'High',
        packageName: 'a',
        installedVersion: '1.0',
        fixedVersion: '',
        packageType: 'rpm',
      );
      const low = GrypeVuln(
        id: 'CVE-2',
        severity: 'Low',
        packageName: 'b',
        installedVersion: '1.0',
        fixedVersion: '',
        packageType: 'rpm',
      );

      final result = dedupeVulns<GrypeVuln>(
        [high, low, high],
        (v, n) => v.withOccurrenceCount(n),
      );

      expect(result.map((v) => v.id), ['CVE-1', 'CVE-2']);
      expect(result.first.occurrenceCount, 2);
      expect(result.last.occurrenceCount, 1);
    });
  });

  testWidgets(
      'le badge ×N s\'affiche uniquement quand occurrenceCount > 1',
      (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(_table(const [
      GrypeVuln(
        id: 'CVE-2026-54513',
        severity: 'Critical',
        packageName: 'jackson-databind',
        installedVersion: '2.17.2',
        fixedVersion: '',
        packageType: 'java-archive',
        occurrenceCount: 2,
      ),
      GrypeVuln(
        id: 'CVE-2024-0001',
        severity: 'High',
        packageName: 'openssl',
        installedVersion: '3.0.1',
        fixedVersion: '3.0.9',
        packageType: 'rpm',
      ),
    ]));
    await tester.pumpAndSettle();

    expect(find.text('×2'), findsOneWidget);
  });

  group('enrichissement exploitabilité', () {
    const log4shell = GrypeVuln(
      id: 'CVE-2021-44228',
      severity: 'Critical',
      packageName: 'log4j-core',
      installedVersion: '2.14.1',
      fixedVersion: '2.15.0',
      packageType: 'java-archive',
    );
    const other = GrypeVuln(
      id: 'CVE-2020-0001',
      severity: 'High',
      packageName: 'foo',
      installedVersion: '1.0',
      fixedVersion: '',
      packageType: 'rpm',
    );

    final exploitMap = {
      'CVE-2021-44228': const ExploitInfo(
        inKev: true,
        epssScore: 0.97,
        epssPercentile: 0.999,
        pocKnown: true,
        pocCount: 12,
        cvssExploitabilityScore: 3.9,
        exploitMaturity: 'High',
      ),
      'CVE-2020-0001': const ExploitInfo(epssScore: 0.02),
    };

    testWidgets('colonnes KEV / EPSS et badges rendus quand exploitById fourni',
        (tester) async {
      tester.view.physicalSize = const Size(1500, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(
          _table(const [log4shell, other], exploitById: exploitMap));
      await tester.pumpAndSettle();

      expect(find.text('KEV'), findsWidgets); // en-tête + chip filtre + pill
      expect(find.text('EPSS 0.97'), findsOneWidget);
      expect(find.text('PoC 12'), findsOneWidget);
      expect(find.textContaining('expl. 3.9'), findsOneWidget);
    });

    testWidgets('le filtre « CISA KEV » ne garde que les CVE du catalogue',
        (tester) async {
      tester.view.physicalSize = const Size(1500, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(
          _table(const [log4shell, other], exploitById: exploitMap));
      await tester.pumpAndSettle();

      expect(find.text('CVE-2020-0001'), findsOneWidget);
      await tester.tap(find.textContaining('CISA KEV ('));
      await tester.pumpAndSettle();
      expect(find.text('CVE-2020-0001'), findsNothing);
      expect(find.text('CVE-2021-44228'), findsOneWidget);
    });

    testWidgets('sans exploitById : aucune colonne ni bouton réseau',
        (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(_table(const [other]));
      await tester.pumpAndSettle();

      expect(find.text('EPSS'), findsNothing);
      expect(find.byIcon(Icons.cloud_done_outlined), findsNothing);
    });
  });

  group('scan_enrichment', () {
    test('normalizeCveId retire le préfixe distro', () {
      expect(normalizeCveId('DEBIAN-CVE-2026-13221'), 'CVE-2026-13221');
      expect(normalizeCveId('CVE-2021-44228'), 'CVE-2021-44228');
      expect(normalizeCveId('GHSA-xxxx'), 'GHSA-xxxx');
    });

    test('seedsFromGrypeJson extrait KEV / EPSS / vecteur CVSS natifs', () {
      const raw = '''
      {"matches":[{"vulnerability":{
        "id":"CVE-2021-44228",
        "cvss":[{"type":"Primary","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","metrics":{"baseScore":10.0}}],
        "knownExploited":[{"cve":"CVE-2021-44228","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"}],
        "epss":[{"cve":"CVE-2021-44228","epss":0.97,"percentile":0.999}]
      }}]}''';
      final seeds = seedsFromGrypeJson(raw);
      final s = seeds['CVE-2021-44228']!;
      expect(s.kev, isTrue);
      expect(s.kevRansomware, isTrue);
      expect(s.epssScore, 0.97);
      expect(s.cvssVector, contains('AV:N'));
    });
  });
}
