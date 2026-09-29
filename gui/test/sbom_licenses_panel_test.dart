import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/license_report.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/sbom_licenses_panel.dart';

FilledButton _generateButton(WidgetTester tester) =>
    tester.widget<FilledButton>(find.widgetWithText(FilledButton, 'Générer'));

final _data = LicenseReportData(
  name: 'Doc',
  totalPackages: 3,
  strongCopyleftPackages: 1,
  weakCopyleftPackages: 0,
  groups: const [
    LicenseGroup('GPL-3.0-only', LicenseCategory.strongCopyleft, [
      LicensePackage('bash', '5.2', ''),
    ]),
    LicenseGroup('MIT', LicenseCategory.permissive, [
      LicensePackage('left-pad', '1.0', ''),
    ]),
    LicenseGroup('', LicenseCategory.unknown, [
      LicensePackage('mystere', '', ''),
    ]),
  ],
);

void main() {
  testWidgets(
    'le bouton "Générer" reste désactivé tant qu\'aucun fichier n\'est '
    'sélectionné, et se réactive à la sélection',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SbomLicensesPanel(
              outputFiles: const [
                OutputFile(path: '/tmp/a.cdx.json', size: '1 KB'),
              ],
              loader: (_) async => _data,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(_generateButton(tester).onPressed, isNull);

      await tester.tap(find.widgetWithText(OutlinedButton, 'Fichiers générés'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('a.cdx.json'));
      await tester.pumpAndSettle();

      expect(find.text('/tmp/a.cdx.json'), findsOneWidget);
      expect(_generateButton(tester).onPressed, isNotNull);
    },
  );

  testWidgets(
    'affiche les licences du SBOM sélectionné (groupes, badges, filtre, '
    'tableau) et le format de rapport',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SbomLicensesPanel(
              outputFiles: const [
                OutputFile(path: '/tmp/a.cdx.json', size: '1 KB'),
              ],
              loader: (_) async => _data,
            ),
          ),
        ),
      );
      await tester.tap(find.widgetWithText(OutlinedButton, 'Fichiers générés'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('a.cdx.json'));
      await tester.pumpAndSettle();

      expect(find.text('GPL-3.0-only'), findsOneWidget);
      expect(find.text('MIT'), findsOneWidget);
      expect(find.text('Sans licence détectée'), findsOneWidget);
      expect(find.text('1 copyleft fort'), findsOneWidget);

      // Filtre : ne garde que le groupe MIT (et déplie ses paquets).
      await tester.enterText(
        find.byKey(const Key('licenses-search')),
        'left-pad',
      );
      await tester.pumpAndSettle();
      expect(find.text('GPL-3.0-only'), findsNothing);
      expect(find.text('left-pad 1.0'), findsOneWidget);

      // Vue tableau.
      await tester.enterText(find.byKey(const Key('licenses-search')), '');
      await tester.tap(find.text('Tableau'));
      await tester.pumpAndSettle();
      expect(find.text('bash'), findsOneWidget);
      expect(find.text('—'), findsOneWidget);

      // Le format change l'extension du fichier de sortie.
      await tester.tap(find.byKey(const Key('licenses-format')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('HTML').last);
      await tester.pumpAndSettle();
      expect(find.text('licences.html'), findsOneWidget);
    },
  );
}
