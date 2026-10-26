import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/i18n.dart';
import 'package:sbom_generator_gui/l10n/l10n.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

// La langue des textes (tr) est globale : on la fixe avec la locale demandée.
Widget _app(Widget home, Locale locale) {
  appLocale = locale;
  return MaterialApp(
    locale: locale,
    localizationsDelegates: GlobalMaterialLocalizations.delegates,
    supportedLocales: supportedAppLocales,
    home: Scaffold(body: home),
  );
}

void main() {
  tearDown(() => appLocale = fallbackLocale);

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

  test('pluriels et paramètres de tr()', () {
    appLocale = const Locale('fr');
    expect(
      tr('{count} vulnérabilités : {details}', {
        'count': 3,
        'details': '3 Low',
      }),
      '3 vulnérabilités : 3 Low',
    );
    expect(isPlural(0), isFalse);
    expect(isPlural(2), isTrue);
    appLocale = const Locale('en');
    expect(
      tr('1 vulnérabilité : {details}', {'details': '1 High'}),
      '1 vulnerability: 1 High',
    );
    expect(
      tr('{count} vulnérabilités exportées → {path}', {
        'count': 2,
        'path': '/tmp/x.csv',
      }),
      '2 vulnerabilities exported → /tmp/x.csv',
    );
    expect(isPlural(0), isTrue);
    expect(isPlural(1), isFalse);
  });
}
