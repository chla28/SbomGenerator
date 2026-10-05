import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/sbom_merge_panel.dart';

FilledButton _mergeButton(WidgetTester tester) =>
    tester.widget<FilledButton>(find.widgetWithText(FilledButton, 'Fusionner'));

void main() {
  testWidgets(
    'le bouton "Fusionner" reste désactivé tant que moins de deux fichiers '
    'sont sélectionnés, et se réactive à la sélection',
    (tester) async {
      // Fenêtre de taille "desktop" réaliste : à la taille par défaut des
      // tests (800x600), la barre d'outils déborde (comportement déjà connu,
      // cf. config_panel_input_test.dart).
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SbomMergePanel(
              outputFiles: const [
                OutputFile(path: '/tmp/a.cdx.json', size: '1 KB'),
                OutputFile(path: '/tmp/b.cdx.json', size: '1 KB'),
              ],
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(_mergeButton(tester).onPressed, isNull);

      // Ouvrir le menu "Fichiers générés" et ajouter le premier fichier.
      await tester.tap(find.widgetWithText(OutlinedButton, 'Fichiers générés'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('a.cdx.json'));
      await tester.pumpAndSettle();

      expect(find.text('a.cdx.json'), findsOneWidget);
      expect(
        _mergeButton(tester).onPressed,
        isNull,
        reason: 'un seul fichier sélectionné, la fusion en requiert deux',
      );

      // Ajouter le second fichier.
      await tester.tap(find.widgetWithText(OutlinedButton, 'Fichiers générés'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('b.cdx.json'));
      await tester.pumpAndSettle();

      expect(_mergeButton(tester).onPressed, isNotNull);

      // Retirer un fichier de la liste : le bouton se désactive à nouveau.
      await tester.tap(find.byIcon(Icons.close).first);
      await tester.pumpAndSettle();

      expect(_mergeButton(tester).onPressed, isNull);
    },
  );
}
