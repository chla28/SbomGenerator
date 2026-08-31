import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

void main() {
  group('looksLikeLocalPath', () {
    test('reconnaît les chemins locaux (/, ./, ../, ~)', () {
      expect(looksLikeLocalPath('/tmp/image.tar'), isTrue);
      expect(looksLikeLocalPath('./image.tar.gz'), isTrue);
      expect(looksLikeLocalPath('../oci_dir'), isTrue);
      expect(looksLikeLocalPath('~/images/alpine.tar'), isTrue);
    });

    test('ne confond pas une référence de registre avec un chemin local', () {
      expect(looksLikeLocalPath('nginx:latest'), isFalse);
      expect(looksLikeLocalPath('ghcr.io/org/app:tag'), isFalse);
      expect(looksLikeLocalPath('alpine'), isFalse);
    });
  });

  testWidgets('ScanSourceToggle bascule entre les deux sources',
      (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    var selected = ScanSourceKind.sbomFile;
    await tester.pumpWidget(StatefulBuilder(
      builder: (context, setState) => MaterialApp(
        home: Scaffold(
          body: ScanSourceToggle(
            kind: selected,
            enabled: true,
            onChanged: (k) => setState(() => selected = k),
          ),
        ),
      ),
    ));
    await tester.pumpAndSettle();

    expect(selected, ScanSourceKind.sbomFile);
    await tester.tap(find.text('Image de conteneur'));
    await tester.pumpAndSettle();
    expect(selected, ScanSourceKind.image);
  });

  testWidgets(
      'GrypePanel : basculer sur "Image de conteneur" remplace le champ '
      'fichier SBOM par le champ image', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const MaterialApp(
      home: Scaffold(
        body: GrypePanel(outputFiles: <OutputFile>[]),
      ),
    ));
    await tester.pumpAndSettle();

    expect(find.text('chemin/vers/sbom.cdx.json'), findsOneWidget);

    await tester.tap(find.text('Image de conteneur'));
    await tester.pumpAndSettle();

    // Le champ "Fichier SBOM" (identifié par son hint) a disparu au profit
    // du champ image + plateforme.
    expect(find.text('chemin/vers/sbom.cdx.json'), findsNothing);
    expect(find.textContaining('nginx:latest'), findsOneWidget);
    expect(find.text('Plateforme'), findsOneWidget);
  });
}
