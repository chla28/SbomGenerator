import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/help_viewer.dart';

// Séparé de help_viewer_search_test.dart — voir la note en tête de
// help_viewer_test.dart.
void main() {
  testWidgets(
    'une recherche sans résultat affiche un message et aucun ListTile',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(const MaterialApp(home: HelpViewerScreen()));
      await tester.pump(const Duration(milliseconds: 500));
      await tester.pump(const Duration(milliseconds: 500));

      await tester.enterText(
        find.byType(TextField),
        'zzz-terme-absent-du-manuel-zzz',
      );
      await tester.pump(const Duration(milliseconds: 300));

      expect(find.byType(ListTile), findsNothing);
      expect(find.textContaining('Aucun chapitre'), findsOneWidget);
    },
  );
}
