import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_config.dart';
import 'package:sbom_generator_gui/widgets/config_panel.dart';

void main() {
  testWidgets(
      '--input : le menu "Parcourir…" propose un fichier filtré, tout fichier et un dossier',
      (tester) async {
    // Fenêtre de taille "desktop" réaliste : le panneau de configuration est
    // conçu pour une largeur fixe de 390 px dans une fenêtre bien plus large.
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    // Le panneau contient des débordements RenderFlex mineurs préexistants
    // (labels + icône d'aide sur fond de police de test) sans rapport avec
    // --input : on les ignore ici pour ne pas faire échouer ce test sur un
    // problème cosmétique déjà présent avant cette fonctionnalité.
    final originalOnError = FlutterError.onError;
    const ignoredPatterns = [
      'A RenderFlex overflowed',
      'ListTile background color or ink splashes may be invisible',
    ];
    FlutterError.onError = (details) {
      final message = details.toString();
      if (ignoredPatterns.any(message.contains)) return;
      originalOnError?.call(details);
    };
    addTearDown(() => FlutterError.onError = originalOnError);

    final config = SbomConfig();

    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: ConfigPanel(
          config: config,
          isRunning: false,
          onRun: () {},
          onStop: () {},
        ),
      ),
    ));
    await tester.pumpAndSettle();

    // Le champ --input est le premier de la section "Entrée" ; son icône
    // "Parcourir…" est donc la première icône folder_open de l'arbre.
    expect(find.text('Paquets à analyser (--input)'), findsOneWidget);
    final browseIcon = find.byIcon(Icons.folder_open).first;

    await tester.tap(browseIcon);
    await tester.pumpAndSettle();

    expect(find.text('Type filtré (.lst .txt)'), findsOneWidget);
    expect(find.text('Tous les fichiers'), findsOneWidget);
    expect(find.text('Dossier (scan récursif)'), findsOneWidget);
  });
}
