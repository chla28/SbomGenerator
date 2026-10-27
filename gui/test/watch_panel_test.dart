import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/watch_panel.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('gui_watch_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<void> pump(WidgetTester tester, Widget panel) async {
    tester.view.physicalSize = const Size(1200, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: panel)));
    await tester.pumpAndSettle();
  }

  void history(String file, List<(String, int)> points) {
    File('${tmp.path}/$file').writeAsStringSync(
      points
          .map(
            (p) =>
                '${jsonEncode({
                  'at': p.$1,
                  'total': p.$2,
                  'added': 0,
                  'resolved': 0,
                  'bySeverity': {'critical': 1, 'high': p.$2 - 1},
                })}\n',
          )
          .join(),
    );
  }

  testWidgets('sans dossier : invite à en choisir un', (tester) async {
    await pump(tester, const WatchPanel());
    expect(find.byKey(const Key('watch-hint')), findsOneWidget);
  });

  testWidgets('dossier sans historique : message dédié', (tester) async {
    await pump(tester, WatchPanel(initialDir: tmp.path));
    expect(find.byKey(const Key('watch-empty')), findsOneWidget);
  });

  testWidgets('historique : carte, variation et graphique par SBOM', (
    tester,
  ) async {
    history('app.cdx.json-1a2b3c4d.history.jsonl', [
      ('2026-01-01T10:00:00Z', 3),
      ('2026-01-02T10:00:00Z', 5),
    ]);
    await pump(tester, WatchPanel(initialDir: tmp.path));
    expect(find.byKey(const Key('history-app.cdx.json')), findsOneWidget);
    expect(find.byKey(const Key('chart-app.cdx.json')), findsOneWidget);
    expect(find.textContaining('5 CVE'), findsOneWidget);
    expect(find.textContaining('(+2)'), findsOneWidget);
  });

  testWidgets('dossier choisi via le sélecteur', (tester) async {
    history('x.cdx.json-00000000.history.jsonl', [('2026-01-01T00:00:00Z', 2)]);
    await pump(tester, WatchPanel(pickDirectory: () async => tmp.path));
    await tester.tap(find.byKey(const Key('watch-pick-dir')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('history-x.cdx.json')), findsOneWidget);
  });

  testWidgets(
    'Vérifier : activé seulement avec SBOM + clé (ou identité + émetteur)',
    (tester) async {
      await pump(
        tester,
        const WatchPanel(
          outputFiles: [OutputFile(path: '/tmp/a.cdx.json', size: '1 KB')],
        ),
      );
      FilledButton button() =>
          tester.widget<FilledButton>(find.byKey(const Key('verify-run')));
      // Le premier SBOM généré est proposé d'office, mais il manque la clé.
      expect(button().onPressed, isNull);

      await tester.enterText(find.byKey(const Key('verify-key')), 'k.pub');
      await tester.pump();
      expect(button().onPressed, isNotNull);

      await tester.enterText(find.byKey(const Key('verify-key')), '');
      await tester.enterText(find.byKey(const Key('verify-identity')), 'me@x');
      await tester.pump();
      expect(button().onPressed, isNull, reason: 'identité sans émetteur');
      await tester.enterText(
        find.byKey(const Key('verify-issuer')),
        'https://issuer',
      );
      await tester.pump();
      expect(button().onPressed, isNotNull);
    },
  );
}
