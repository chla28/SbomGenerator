import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/sbom_licenses_panel.dart';

FilledButton _generateButton(WidgetTester tester) =>
    tester.widget<FilledButton>(find.widgetWithText(FilledButton, 'Générer'));

void main() {
  testWidgets(
      'le bouton "Générer" reste désactivé tant qu\'aucun fichier n\'est '
      'sélectionné, et se réactive à la sélection', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: SbomLicensesPanel(outputFiles: const [
          OutputFile(path: '/tmp/a.cdx.json', size: '1 KB'),
        ]),
      ),
    ));
    await tester.pumpAndSettle();

    expect(_generateButton(tester).onPressed, isNull);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Fichiers générés'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('a.cdx.json'));
    await tester.pumpAndSettle();

    expect(find.text('/tmp/a.cdx.json'), findsOneWidget);
    expect(_generateButton(tester).onPressed, isNotNull);
  });
}
