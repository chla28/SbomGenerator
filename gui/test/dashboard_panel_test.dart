import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/dashboard_panel.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/osv_panel.dart';
import 'package:sbom_generator_gui/widgets/trivy_panel.dart';

void main() {
  testWidgets(
      'Comparaison inter-scanners affiche l\'union complète (pas seulement les CVE communes)',
      (tester) async {
    tester.view.physicalSize = const Size(1400, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    // CVE-COMMON : vue par les 3 scanners.
    // CVE-PARTIAL : vue par Grype + OSV seulement.
    // CVE-GRYPE-ONLY : vue par Grype seulement — c'est celle qui devait
    // disparaître avec l'ancien filtre "≥ 2 scanners".
    final grype = [
      const GrypeVuln(
        id: 'CVE-COMMON',
        severity: 'Critical',
        packageName: 'pkg-a',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        packageType: 'rpm',
      ),
      const GrypeVuln(
        id: 'CVE-PARTIAL',
        severity: 'High',
        packageName: 'pkg-b',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        packageType: 'rpm',
      ),
      const GrypeVuln(
        id: 'CVE-GRYPE-ONLY',
        severity: 'Medium',
        packageName: 'pkg-c',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        packageType: 'rpm',
      ),
    ];
    final osv = [
      const OsvVuln(
        id: 'CVE-COMMON',
        severity: 'Critical',
        packageName: 'pkg-a',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        ecosystem: 'RPM',
      ),
      const OsvVuln(
        id: 'CVE-PARTIAL',
        severity: 'High',
        packageName: 'pkg-b',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        ecosystem: 'RPM',
      ),
    ];
    final trivy = [
      const TrivyVuln(
        id: 'CVE-COMMON',
        severity: 'Critical',
        packageName: 'pkg-a',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        title: 'pkg-a vulnerability',
      ),
    ];

    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: DashboardPanel(
          grypeVulns: grype,
          osvVulns: osv,
          trivyVulns: trivy,
        ),
      ),
    ));
    await tester.pumpAndSettle();

    // Titre : union complète = 3 CVE uniques, pas seulement les 2 "≥2 scanners".
    expect(find.text('Comparaison inter-scanners (3 CVE)'), findsOneWidget);

    // Les 3 CVE apparaissent bien dans le tableau détaillé, y compris celle
    // vue par un seul scanner (c'était exactement le problème signalé).
    expect(find.text('CVE-COMMON'), findsOneWidget);
    expect(find.text('CVE-PARTIAL'), findsOneWidget);
    expect(find.text('CVE-GRYPE-ONLY'), findsOneWidget);

    // La CVE isolée (1 seul scanner) porte un marqueur visuel distinct.
    expect(
      find.byTooltip('Vu par un seul scanner sur 3'),
      findsOneWidget,
    );
  });

  testWidgets(
      'un CVE préfixé par OSV-Scanner (DEBIAN-CVE-xxxx) est fusionné avec '
      'le même CVE nu rapporté par Grype/Trivy', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final grype = [
      const GrypeVuln(
        id: 'CVE-2026-13221',
        severity: 'High',
        packageName: 'valkey',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        packageType: 'deb',
      ),
    ];
    // OSV-Scanner préfixe ses avis Debian par l'origine (DEBIAN-) là où
    // Grype/Trivy rapportent l'ID CVE nu — sans normalisation, la même
    // vulnérabilité comptait comme deux lignes distinctes.
    final osv = [
      const OsvVuln(
        id: 'DEBIAN-CVE-2026-13221',
        severity: 'High',
        packageName: 'valkey',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        ecosystem: 'Debian',
      ),
    ];
    final trivy = [
      const TrivyVuln(
        id: 'CVE-2026-13221',
        severity: 'HIGH',
        packageName: 'valkey',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        title: 'valkey vulnerability',
      ),
    ];

    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: DashboardPanel(
          grypeVulns: grype,
          osvVulns: osv,
          trivyVulns: trivy,
        ),
      ),
    ));
    await tester.pumpAndSettle();

    // Une seule ligne, sous sa forme CVE nue — pas de doublon
    // DEBIAN-CVE-2026-13221 / CVE-2026-13221, et pas de marqueur "vu par un
    // seul scanner" puisque les 3 scanners l'ont bien détectée.
    expect(find.text('Comparaison inter-scanners (1 CVE)'), findsOneWidget);
    expect(find.text('CVE-2026-13221'), findsOneWidget);
    expect(find.text('DEBIAN-CVE-2026-13221'), findsNothing);
    expect(find.byTooltip('Vu par un seul scanner sur 3'), findsNothing);
  });

  testWidgets(
      'le bouton "Exporter en AsciiDoc + PDF" est désactivé tant qu\'aucun '
      'scanner n\'a été exécuté', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const MaterialApp(
      home: Scaffold(
        body: DashboardPanel(
          grypeVulns: null,
          osvVulns: null,
          trivyVulns: null,
        ),
      ),
    ));
    await tester.pumpAndSettle();

    final button = tester.widget<IconButton>(
        find.widgetWithIcon(IconButton, Icons.picture_as_pdf_outlined));
    expect(button.onPressed, isNull);
  });

  testWidgets(
      'le bouton "Exporter en AsciiDoc + PDF" se réactive dès qu\'un '
      'scanner a été exécuté (même sans vulnérabilité trouvée)',
      (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const MaterialApp(
      home: Scaffold(
        body: DashboardPanel(
          grypeVulns: [], // scanner exécuté, aucune vulnérabilité trouvée
          osvVulns: null,
          trivyVulns: null,
        ),
      ),
    ));
    await tester.pumpAndSettle();

    final button = tester.widget<IconButton>(
        find.widgetWithIcon(IconButton, Icons.picture_as_pdf_outlined));
    expect(button.onPressed, isNotNull);
  });
}
