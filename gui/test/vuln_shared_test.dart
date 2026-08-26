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
}
