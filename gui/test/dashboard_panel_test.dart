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
}
