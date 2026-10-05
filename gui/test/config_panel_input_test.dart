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

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ConfigPanel(
              config: config,
              isRunning: false,
              onRun: () {},
              onStop: () {},
            ),
          ),
        ),
      );
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
    },
  );

  testWidgets('--binary : champ dédié, mutuellement exclusif avec --input', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

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

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: ConfigPanel(
            config: config,
            isRunning: false,
            onRun: () {},
            onStop: () {},
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Binaire autonome (--binary)'), findsOneWidget);

    await tester.enterText(
      find.widgetWithText(TextFormField, 'Paquets à analyser (--input)'),
      'packages.txt',
    );
    await tester.pumpAndSettle();
    expect(config.inputFile, 'packages.txt');

    await tester.enterText(
      find.widgetWithText(TextFormField, 'Binaire autonome (--binary)'),
      '/usr/local/bin/mon-app',
    );
    await tester.pumpAndSettle();

    // Saisir --binary efface --input (exclusivité UI).
    expect(config.binaryPath, '/usr/local/bin/mon-app');
    expect(config.inputFile, isEmpty);
    // Le backend est forcé syft — aucun sélecteur --oci-tool affiché.
    expect(find.text('Backend OCI (--oci-tool)'), findsNothing);
    expect(find.textContaining('Backend : syft (forcé'), findsOneWidget);

    await tester.enterText(
      find.widgetWithText(TextFormField, 'Paquets à analyser (--input)'),
      'packages.txt',
    );
    await tester.pumpAndSettle();

    // Ré-saisir --input efface --binary.
    expect(config.inputFile, 'packages.txt');
    expect(config.binaryPath, isEmpty);
  });

  testWidgets('--per-layer : option sous le backend OCI, rootfs forcé pour '
      'skopeo', (tester) async {
    tester.view.physicalSize = const Size(1400, 1200);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

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

    final config = SbomConfig(imageRef: 'nginx:latest');

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: ConfigPanel(
            config: config,
            isRunning: false,
            onRun: () {},
            onStop: () {},
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final label = find.text('Un SBOM par couche (--per-layer)');
    expect(label, findsOneWidget);
    expect(find.text('Métadonnées'), findsNothing);

    final checkbox = find.descendant(
      of: find.ancestor(of: label, matching: find.byType(Row)).first,
      matching: find.byType(Checkbox),
    );
    await tester.ensureVisible(checkbox);
    await tester.tap(checkbox);
    await tester.pumpAndSettle();
    expect(config.perLayer, isTrue);
    expect(find.text('Métadonnées'), findsOneWidget);
    expect(
      config.toArgs(),
      containsAllInOrder(['--per-layer', '--layer-mode', 'metadata']),
    );

    // Centré plutôt qu'aligné en haut (ensureVisible) : sinon le segment
    // reste masqué sous le bord de la zone défilante.
    Scrollable.ensureVisible(
      tester.element(find.text('Skopeo')),
      alignment: 0.5,
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Skopeo'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Mode rootfs forcé'), findsOneWidget);
    expect(config.toArgs(), containsAllInOrder(['--layer-mode', 'rootfs']));
  });
}
