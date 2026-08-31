import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

const _severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Negligible'];

Widget _table(List<GrypeVuln> vulns) => MaterialApp(
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
}
