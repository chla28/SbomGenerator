import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/l10n/l10n.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

Widget _app(Widget home, Locale locale) => MaterialApp(
  locale: locale,
  localizationsDelegates: AppLocalizations.localizationsDelegates,
  supportedLocales: AppLocalizations.supportedLocales,
  home: Scaffold(body: home),
);

void main() {
  testWidgets('onglet Grype en anglais', (tester) async {
    tester.view.physicalSize = const Size(1400, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      _app(const GrypePanel(outputFiles: <OutputFile>[]), const Locale('en')),
    );
    await tester.pumpAndSettle();

    expect(find.text('SBOM file'), findsWidgets);
    expect(find.text('Container image'), findsOneWidget);
    expect(find.text('Analyze'), findsOneWidget);
    expect(find.text('Browse'), findsWidgets);
    expect(
      find.textContaining('Choose an SBOM file or a container image'),
      findsOneWidget,
    );
    expect(find.text('Analyser'), findsNothing);

    // Erreur de validation traduite.
    await tester.tap(find.text('Analyze'));
    await tester.pumpAndSettle();
    expect(find.text('Please select an SBOM file.'), findsOneWidget);

    // Popup CLI.
    await tester.tap(find.text('CLI command'));
    await tester.pumpAndSettle();
    expect(find.text('Command line'), findsOneWidget);
    expect(find.text('Command run by the tab'), findsOneWidget);
    expect(find.text('sbom-generator scan equivalent'), findsOneWidget);
    expect(find.text('Close'), findsOneWidget);
  });

  testWidgets('tableau de vulnérabilités : en-têtes et pluriels FR / EN', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final vulns = GrypeVuln.fromJson(
      jsonEncode({
        'matches': [
          {
            'vulnerability': {'id': 'CVE-2026-0001', 'severity': 'High'},
            'artifact': {'name': 'zlib', 'version': '1.3', 'type': 'apk'},
          },
        ],
      }),
    );
    Widget table() => VulnTableView<GrypeVuln>(
      vulns: vulns,
      parseFailedMessage: '',
      severityOrder: const ['High'],
      toolName: 'Grype',
      csvDialogTitle: '',
      csvFileName: 'g.csv',
      csvHeader: 'Sévérité,CVE',
      csvRow: (v) => [v.severity, v.id],
    );

    await tester.pumpWidget(_app(table(), const Locale('en')));
    await tester.pumpAndSettle();
    expect(find.text('SEVERITY'), findsOneWidget);
    expect(find.text('PACKAGE'), findsOneWidget);
    expect(find.byTooltip('Export CSV'), findsOneWidget);

    await tester.pumpWidget(_app(table(), const Locale('fr')));
    await tester.pumpAndSettle();
    expect(find.text('SÉVÉRITÉ'), findsOneWidget);
    expect(find.byTooltip('Exporter CSV'), findsOneWidget);
  });

  test('pluriels ICU', () {
    final fr = lookupAppLocalizations(const Locale('fr'));
    final en = lookupAppLocalizations(const Locale('en'));
    expect(fr.scanSummary(1, '1 High'), '1 vulnérabilité : 1 High');
    expect(fr.scanSummary(3, '3 Low'), '3 vulnérabilités : 3 Low');
    expect(en.scanSummary(1, '1 High'), '1 vulnerability: 1 High');
    expect(
      en.vulnTableExported(2, '/tmp/x.csv'),
      '2 vulnerabilities exported → /tmp/x.csv',
    );
    expect(en.layerScanStepLayer(2, 9), 'Layer 2/9…');
  });
}
