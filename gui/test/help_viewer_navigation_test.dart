import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/help_viewer.dart';

// Séparé de help_viewer_test.dart — voir la note en tête de ce fichier.
void main() {
  testWidgets('change de chapitre au clic dans le sommaire', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const MaterialApp(home: HelpViewerScreen()));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 500));

    await tester.tap(find.byType(ListTile).at(1));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 500));

    // Le chapitre 1 (Prérequis & installation) doit maintenant être affiché
    // — un texte propre au chapitre 0 (Introduction) ne doit plus l'être.
    expect(find.textContaining('Qu’est-ce qu’un SBOM'), findsNothing);
  });
}
