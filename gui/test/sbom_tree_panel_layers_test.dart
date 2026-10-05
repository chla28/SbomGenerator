import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/layer_selector.dart';
import 'package:sbom_generator_gui/widgets/sbom_tree_panel.dart';

Map<String, dynamic> _cdx(
  List<Map<String, dynamic>> components, {
  List<Map<String, String>> rootProps = const [],
}) => {
  'bomFormat': 'CycloneDX',
  'specVersion': '1.6',
  'metadata': {
    'component': {'name': 'app', 'version': '1.0', 'properties': rootProps},
  },
  'components': components,
};

Map<String, dynamic> _comp(String name, Map<String, String> layer) => {
  'type': 'library',
  'name': name,
  'version': '1.0',
  'properties': [
    for (final e in layer.entries)
      {'name': 'sbom_generator:layer:${e.key}', 'value': e.value},
  ],
};

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('tree_layers_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  testWidgets(
    'SBOM global --per-layer : charge le global, sélecteur de couche et '
    'regroupement par couche',
    (tester) async {
      final global = '${tmp.path}/app.cdx.json';
      final layer1 = '${tmp.path}/app.layer-01-aaaaaaaaaaaa.cdx.json';
      await tester.runAsync(() async {
        File(global).writeAsStringSync(
          jsonEncode(
            _cdx(
              [
                _comp('musl', {'index': '1'}),
                _comp('curl', {'index': '2'}),
              ],
              rootProps: [
                {
                  'name': 'sbom_generator:layers:001',
                  'value': jsonEncode({
                    'index': 1,
                    'added': 1,
                    'modified': 0,
                    'removed': 0,
                    'createdBy': 'ADD base',
                  }),
                },
              ],
            ),
          ),
        );
        File(layer1).writeAsStringSync(
          jsonEncode(
            _cdx([
              _comp('musl', {'change': 'added'}),
            ]),
          ),
        );
        File(
          '${tmp.path}/app.layer-02-bbbbbbbbbbbb.cdx.json',
        ).writeAsStringSync(
          jsonEncode(
            _cdx([
              _comp('curl', {'change': 'added'}),
            ]),
          ),
        );
      });

      // Un SBOM de couche listé avant le global ne doit pas être ouvert par
      // défaut.
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SbomTreePanel(
              outputFiles: [
                OutputFile(path: layer1, size: '1 KB'),
                OutputFile(path: global, size: '1 KB'),
              ],
            ),
          ),
        ),
      );
      // Lecture réelle des fichiers : on laisse les E/S progresser hors de
      // l'horloge simulée, jusqu'à la fin du chargement.
      for (
        var i = 0;
        i < 40 && find.byType(LayerSelector).evaluate().isEmpty;
        i++
      ) {
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 25)),
        );
        await tester.pump();
      }

      expect(find.byType(LayerSelector), findsOneWidget);
      expect(find.text('2 couches :'), findsOneWidget);
      expect(find.text('SBOM global'), findsOneWidget);
      expect(find.text('Couche'), findsOneWidget); // segment de regroupement

      await tester.tap(find.text('Couche'));
      await tester.pumpAndSettle();
      expect(find.text('Couche 01'), findsOneWidget);
      expect(find.text('Couche 02'), findsOneWidget);
    },
  );
}
