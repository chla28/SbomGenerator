import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/help_viewer.dart';

// Seul dans son fichier volontairement — voir la note en tête de
// help_viewer_test.dart (rootBundle.loadString bloque au second testWidgets
// d'un même fichier). Voir help_viewer_search_empty_test.dart pour le cas
// "aucun résultat".
void main() {
  testWidgets(
      'la recherche filtre le sommaire par contenu, avec extrait, et se '
      'réinitialise au clic sur Effacer', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const MaterialApp(home: HelpViewerScreen()));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 500));

    // Avant recherche : 21 chapitres au sommaire (ListView.builder ne
    // construit que les entrées visibles, d'où >= plutôt qu'un compte exact).
    final initialCount = tester.widgetList(find.byType(ListTile)).length;
    expect(initialCount, greaterThan(5));

    // "ANSSI" n'apparaît que dans le contenu du chapitre Introduction (pas
    // dans son titre, ni dans aucun autre chapitre) — un seul résultat
    // attendu, avec un extrait de contexte affiché sous le titre.
    await tester.enterText(find.byType(TextField), 'ANSSI');
    await tester.pump(const Duration(milliseconds: 300));

    expect(find.byType(ListTile), findsOneWidget);
    // "1. Introduction" apparaît deux fois : l'entrée de sommaire filtrée
    // et le titre <h2> du contenu déjà affiché à droite (chapitre 0 par
    // défaut, inchangé par la recherche elle-même).
    expect(find.textContaining('1. Introduction'), findsWidgets);
    expect(find.textContaining('ANSSI'), findsWidgets); // titre + extrait

    // Effacer la recherche restaure le sommaire complet.
    await tester.tap(find.byIcon(Icons.clear));
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.widgetList(find.byType(ListTile)).length, initialCount);
  });
}
