import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/help_viewer.dart';

// Seul dans son fichier volontairement — voir help_viewer_test.dart
// (rootBundle.loadString bloque au second testWidgets d'un même fichier).
void main() {
  testWidgets('recherche dans le chapitre : compteur, suivant / précédent', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const MaterialApp(home: HelpViewerScreen()));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 500));

    // Pas de barre d'occurrences sans recherche.
    expect(find.byKey(const Key('help-hit-count')), findsNothing);

    await tester.enterText(find.byType(TextField), 'SBOM');
    await tester.pump(const Duration(milliseconds: 300));

    String counter() =>
        tester.widget<Text>(find.byKey(const Key('help-hit-count'))).data!;
    final first = counter();
    final total = int.parse(RegExp(r'sur (\d+)').firstMatch(first)!.group(1)!);
    expect(first, startsWith('Occurrence 1 sur '));
    expect(total, greaterThan(2));

    await tester.tap(find.byIcon(Icons.keyboard_arrow_down));
    await tester.pump(const Duration(milliseconds: 300));
    expect(counter(), 'Occurrence 2 sur $total');

    // Précédent depuis la première : retour à la dernière (en boucle).
    await tester.tap(find.byIcon(Icons.keyboard_arrow_up));
    await tester.pump(const Duration(milliseconds: 300));
    await tester.tap(find.byIcon(Icons.keyboard_arrow_up));
    await tester.pump(const Duration(milliseconds: 300));
    expect(counter(), 'Occurrence $total sur $total');

    // F3 : occurrence suivante (clavier).
    await tester.tap(find.byType(TextField));
    await tester.sendKeyEvent(LogicalKeyboardKey.f3);
    await tester.pump(const Duration(milliseconds: 300));
    expect(counter(), 'Occurrence 1 sur $total');

    // Terme absent du chapitre affiché (présent ailleurs : aucun) : message.
    await tester.enterText(find.byType(TextField), 'zzzabsent');
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.text('Aucune occurrence dans ce chapitre'), findsOneWidget);
  });
}
