import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/help_viewer.dart';

// NOTE : ce test reste seul dans son fichier volontairement. Exécuter deux
// testWidgets dans le même fichier, chacun chargeant un asset via
// rootBundle.loadString (ici toc.json), fait planter le second au chargement
// (Future qui ne se résout jamais) — un défaut de l'isolation des assets
// entre tests dans ce binding Flutter/test, reproduit même avec un widget
// minimal sans rapport avec HelpViewerScreen ni flutter_html. Voir
// help_viewer_navigation_test.dart pour le test de changement de chapitre.
void main() {
  testWidgets('charge le sommaire et affiche le premier chapitre par défaut',
      (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const MaterialApp(home: HelpViewerScreen()));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 500));

    // Sommaire chargé depuis assets/help/manual/toc.json — "1. Introduction"
    // apparaît deux fois (entrée de sommaire + titre <h2> du contenu).
    expect(find.text('1. Introduction'), findsWidgets);
    expect(find.textContaining('Onglet Tableau de bord'), findsOneWidget);

    // Contenu du premier chapitre affiché par défaut.
    expect(find.textContaining('Qu’est-ce qu’un SBOM'), findsWidgets);
  });
}
