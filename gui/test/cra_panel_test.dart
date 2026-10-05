import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/cra_panel.dart';

void main() {
  testWidgets('CraPanel : formulaire, auto-remplissage du SBOM, boutons', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: CraPanel(
            outputFiles: [
              OutputFile(path: '/tmp/out/sbom.cdx.json', size: '1 KB'),
              OutputFile(path: '/tmp/out/sbom.pdf', size: '1 KB'),
            ],
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      find.text('Rapport de conformité — Cyber Resilience Act'),
      findsOneWidget,
    );
    // Le champ SBOM est pré-rempli avec le .cdx.json (pas le .pdf).
    expect(find.text('/tmp/out/sbom.cdx.json'), findsOneWidget);
    expect(find.widgetWithText(FilledButton, 'Évaluer'), findsOneWidget);
    expect(
      find.widgetWithText(OutlinedButton, 'Exporter le rapport PDF'),
      findsOneWidget,
    );

    // Le formulaire de métadonnées est repliable.
    expect(find.text('Métadonnées produit (facultatif)'), findsOneWidget);
    await tester.tap(find.text('Métadonnées produit (facultatif)'));
    await tester.pumpAndSettle();
    expect(find.widgetWithText(TextField, 'Fabricant'), findsOneWidget);
  });
}
