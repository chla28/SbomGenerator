import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/sbom_viewer_panel.dart';

void main() {
  testWidgets('affiche l\'état vide avec un bouton pour ouvrir un fichier', (
    tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: SbomViewerPanel())),
    );
    await tester.pumpAndSettle();

    expect(find.text('Aucun fichier SBOM chargé'), findsOneWidget);
    expect(find.text('Ouvrir un fichier SBOM…'), findsOneWidget);
  });
}
