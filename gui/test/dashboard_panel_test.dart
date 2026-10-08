import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sbom_generator_gui/models/layer_scan.dart';
import 'package:sbom_generator_gui/services/scan_enrichment.dart';
import 'package:sbom_generator_gui/widgets/dashboard_panel.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/osv_panel.dart';
import 'package:sbom_generator_gui/widgets/trivy_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

GrypeVuln _g(String id, String sev) => GrypeVuln(
  id: id,
  severity: sev,
  packageName: 'pkg',
  installedVersion: '1.0',
  fixedVersion: '1.1',
  packageType: 'rpm',
);
OsvVuln _o(String id, String sev) => OsvVuln(
  id: id,
  severity: sev,
  packageName: 'pkg',
  installedVersion: '1.0',
  fixedVersion: '1.1',
  ecosystem: 'RPM',
);
TrivyVuln _t(String id, String sev) => TrivyVuln(
  id: id,
  severity: sev,
  packageName: 'pkg',
  installedVersion: '1.0',
  fixedVersion: '1.1',
  title: 't',
);

void main() {
  remediationTests();
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

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: DashboardPanel(
              grypeVulns: grype,
              osvVulns: osv,
              trivyVulns: trivy,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Titre : union complète = 3 CVE uniques, pas seulement les 2 "≥2 scanners".
      expect(find.text('Comparaison inter-scanners (3 CVE)'), findsOneWidget);

      // Les 3 CVE apparaissent bien dans le tableau détaillé, y compris celle
      // vue par un seul scanner (c'était exactement le problème signalé).
      expect(find.text('CVE-COMMON'), findsOneWidget);
      expect(find.text('CVE-PARTIAL'), findsOneWidget);
      expect(find.text('CVE-GRYPE-ONLY'), findsOneWidget);

      // La CVE isolée (1 seul scanner) porte un marqueur visuel distinct.
      expect(find.byTooltip('Vu par un seul scanner sur 3'), findsOneWidget);
    },
  );

  testWidgets(
    'un CVE préfixé par OSV-Scanner (DEBIAN-CVE-xxxx) est fusionné avec '
    'le même CVE nu rapporté par Grype/Trivy',
    (tester) async {
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

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: DashboardPanel(
              grypeVulns: grype,
              osvVulns: osv,
              trivyVulns: trivy,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Une seule ligne, sous sa forme CVE nue — pas de doublon
      // DEBIAN-CVE-2026-13221 / CVE-2026-13221, et pas de marqueur "vu par un
      // seul scanner" puisque les 3 scanners l'ont bien détectée.
      expect(find.text('Comparaison inter-scanners (1 CVE)'), findsOneWidget);
      expect(find.text('CVE-2026-13221'), findsOneWidget);
      expect(find.text('DEBIAN-CVE-2026-13221'), findsNothing);
      expect(find.byTooltip('Vu par un seul scanner sur 3'), findsNothing);
    },
  );

  testWidgets(
    'le bouton "Exporter en AsciiDoc + PDF" est désactivé tant qu\'aucun '
    'scanner n\'a été exécuté',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: DashboardPanel(
              grypeVulns: null,
              osvVulns: null,
              trivyVulns: null,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      final button = tester.widget<IconButton>(
        find.widgetWithIcon(IconButton, Icons.picture_as_pdf_outlined),
      );
      expect(button.onPressed, isNull);
    },
  );

  testWidgets('le bouton "Exporter en AsciiDoc + PDF" se réactive dès qu\'un '
      'scanner a été exécuté (même sans vulnérabilité trouvée)', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: DashboardPanel(
            grypeVulns: [], // scanner exécuté, aucune vulnérabilité trouvée
            osvVulns: null,
            trivyVulns: null,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final button = tester.widget<IconButton>(
      find.widgetWithIcon(IconButton, Icons.picture_as_pdf_outlined),
    );
    expect(button.onPressed, isNotNull);
  });

  group('tri de la comparaison inter-scanners', () {
    // AAA : Medium, Grype seul, EPSS 0.80
    // BBB : Low, les 3 scanners, EPSS 0.05, CISA KEV
    // CCC : Critical, Trivy seul, EPSS 0.30
    final grype = [_g('CVE-AAA', 'Medium'), _g('CVE-BBB', 'Low')];
    final osv = [_o('CVE-BBB', 'Low')];
    final trivy = [_t('CVE-BBB', 'Low'), _t('CVE-CCC', 'Critical')];
    final exploit = {
      'CVE-AAA': const ExploitInfo(epssScore: 0.80, epssPercentile: 0.97),
      'CVE-BBB': const ExploitInfo(inKev: true, epssScore: 0.05),
      'CVE-CCC': const ExploitInfo(epssScore: 0.30),
    };

    Future<void> pump(
      WidgetTester tester, {
      Map<String, ExploitInfo> ex = const {},
    }) async {
      tester.view.physicalSize = const Size(1400, 1400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: DashboardPanel(
              grypeVulns: grype,
              osvVulns: osv,
              trivyVulns: trivy,
              exploitById: ex,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
    }

    List<String> order(WidgetTester tester) {
      final ids = ['CVE-AAA', 'CVE-BBB', 'CVE-CCC'];
      ids.sort(
        (a, b) => tester
            .getTopLeft(find.text(a))
            .dy
            .compareTo(tester.getTopLeft(find.text(b)).dy),
      );
      return ids;
    }

    testWidgets('défaut sans enrichissement : sévérité décroissante', (
      tester,
    ) async {
      await pump(tester);
      expect(order(tester), ['CVE-CCC', 'CVE-AAA', 'CVE-BBB']);
    });

    testWidgets('défaut avec enrichissement : KEV puis EPSS décroissant', (
      tester,
    ) async {
      await pump(tester, ex: exploit);
      expect(order(tester), ['CVE-BBB', 'CVE-AAA', 'CVE-CCC']);
    });

    testWidgets('clic sur « CVE / ID » : ordre alphabétique, puis inversé', (
      tester,
    ) async {
      await pump(tester, ex: exploit);
      await tester.tap(find.widgetWithText(SortHeader, 'CVE / ID'));
      await tester.pumpAndSettle();
      expect(order(tester), ['CVE-AAA', 'CVE-BBB', 'CVE-CCC']);
      await tester.tap(find.widgetWithText(SortHeader, 'CVE / ID'));
      await tester.pumpAndSettle();
      expect(order(tester), ['CVE-CCC', 'CVE-BBB', 'CVE-AAA']);
    });

    testWidgets('clic sur « EPSS » : score décroissant, puis croissant', (
      tester,
    ) async {
      await pump(tester, ex: exploit);
      await tester.tap(find.widgetWithText(SortHeader, 'EPSS'));
      await tester.pumpAndSettle();
      expect(order(tester), ['CVE-AAA', 'CVE-CCC', 'CVE-BBB']);
      await tester.tap(find.widgetWithText(SortHeader, 'EPSS'));
      await tester.pumpAndSettle();
      expect(order(tester), ['CVE-BBB', 'CVE-CCC', 'CVE-AAA']);
    });

    testWidgets('clic sur « Trivy » : CVE vues par Trivy en tête', (
      tester,
    ) async {
      await pump(tester, ex: exploit);
      await tester.tap(find.widgetWithText(SortHeader, 'Trivy'));
      await tester.pumpAndSettle();
      // BBB et CCC (vus par Trivy) avant AAA ; départage par id.
      expect(order(tester), ['CVE-BBB', 'CVE-CCC', 'CVE-AAA']);
    });

    testWidgets('pas de colonnes KEV / EPSS sans enrichissement', (
      tester,
    ) async {
      await pump(tester);
      expect(find.widgetWithText(SortHeader, 'EPSS'), findsNothing);
      expect(find.widgetWithText(SortHeader, 'KEV'), findsNothing);
    });

    testWidgets(
      'clic sur une ligne : déplie le détail de la CVE, re-clic ferme',
      (tester) async {
        await pump(tester, ex: exploit);
        // Détail fermé par défaut.
        expect(find.text('Rapporté par'.toUpperCase()), findsNothing);

        await tester.tap(find.text('CVE-BBB').first);
        await tester.pumpAndSettle();
        // Section du panneau de détail visible + infos KEV de CVE-BBB.
        expect(find.text('RAPPORTÉ PAR'), findsOneWidget);
        expect(
          find.textContaining('exploitée activement dans la nature'),
          findsOneWidget,
        );
        expect(find.text('NVD'), findsOneWidget);

        await tester.tap(find.byIcon(Icons.expand_less));
        await tester.pumpAndSettle();
        expect(find.text('RAPPORTÉ PAR'), findsNothing);
      },
    );
  });

  testWidgets('analyse par couche : section « Couches » et colonne Couche(s)', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    LayerScanResult scan(Map<String, Set<int>> byKey) => LayerScanResult(
      mode: LayerScanMode.attribute,
      layers: const [
        LayerInfo(
          index: 1,
          digest: 'sha256:aaaaaaaaaaaaaaaa',
          createdBy: 'ADD base',
        ),
        LayerInfo(
          index: 2,
          digest: 'sha256:bbbbbbbbbbbbbbbb',
          createdBy: 'RUN apk add curl',
        ),
      ],
      layersByKey: byKey,
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: DashboardPanel(
            grypeVulns: [
              _g('CVE-2026-0001', 'Critical'),
              _g('CVE-2026-0002', 'High'),
            ],
            osvVulns: [_o('CVE-2026-0002', 'High')],
            trivyVulns: null,
            layerScans: {
              'Grype': scan({
                vulnLayerKey('CVE-2026-0001', 'pkg', '1.0'): {1},
                vulnLayerKey('CVE-2026-0002', 'pkg', '1.0'): {2},
              }),
              'OSV-Scanner': scan({
                vulnLayerKey('CVE-2026-0002', 'pkg', '1.0'): {2},
              }),
            },
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Couches de l\'image (2)'), findsOneWidget);
    expect(find.text('RUN apk add curl'), findsOneWidget);
    expect(find.text('COUCHE(S)'), findsOneWidget);
    expect(find.textContaining('Grype : rattachement'), findsOneWidget);
  });

  testWidgets('menu du seuil de sévérité : All par défaut, choix mémorisé', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    tester.view.physicalSize = const Size(1400, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: DashboardPanel(
            grypeVulns: [_g('CVE-2026-0001', 'High')],
            osvVulns: null,
            trivyVulns: null,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('All'), findsOneWidget);

    await tester.tap(find.byKey(const Key('report-severity')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('≥ High').last);
    await tester.pumpAndSettle();
    expect(find.text('≥ High'), findsOneWidget);
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('dashboard_report_severity_v1'), 'high');

    // Relu au prochain affichage.
    await tester.pumpWidget(const SizedBox());
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: DashboardPanel(
            grypeVulns: [_g('CVE-2026-0001', 'High')],
            osvVulns: null,
            trivyVulns: null,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('≥ High'), findsOneWidget);
  });
}

void remediationTests() {
  testWidgets('section Remédiation : paquet à mettre à jour, dépliable', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: DashboardPanel(
            grypeVulns: [_g('CVE-1', 'Critical'), _g('CVE-2', 'High')],
            osvVulns: null,
            trivyVulns: null,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('remediation-section')), findsOneWidget);
    expect(find.text('pkg 1.0 → 1.1'), findsOneWidget);
    expect(find.textContaining('2 CVE corrigées'), findsOneWidget);

    await tester.tap(find.text('pkg 1.0 → 1.1'));
    await tester.pumpAndSettle();
    expect(find.textContaining('CVE-1', findRichText: true), findsWidgets);
  });
}
