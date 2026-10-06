import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/vex.dart';
import 'package:sbom_generator_gui/services/vex_controller.dart';
import 'package:sbom_generator_gui/widgets/cve_detail.dart';
import 'package:sbom_generator_gui/widgets/vex_ui.dart';

const _detail = CveDetail(
  id: 'CVE-2024-1',
  views: [
    ScannerCveView(
      scanner: 'Grype',
      severity: 'High',
      packageName: 'foo',
      installedVersion: '1.0',
      fixedVersion: '1.1',
    ),
  ],
);

Widget _app(Widget child) => MaterialApp(
  home: Scaffold(body: SingleChildScrollView(child: child)),
);

void main() {
  testWidgets('fiche CVE : déclarer, modifier et retirer une déclaration VEX', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 1600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    final vex = VexController();
    await tester.pumpWidget(
      _app(
        VexScope(
          controller: vex,
          child: const CveDetailPanel(detail: _detail),
        ),
      ),
    );

    await tester.tap(find.byKey(const Key('vex-declare')));
    await tester.pumpAndSettle();

    // « non affectée » exige une justification.
    await tester.tap(find.byKey(const Key('vex-save')));
    await tester.pump();
    expect(
      find.text('Une justification est requise pour « non affectée ».'),
      findsOneWidget,
    );
    expect(vex.isEmpty, isTrue);

    await tester.tap(find.byKey(const Key('vex-justification')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('code vulnérable jamais exécuté').last);
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const Key('vex-impact')),
      'jamais appelé',
    );
    await tester.tap(find.byKey(const Key('vex-save')));
    await tester.pumpAndSettle();

    final s = vex.statements.single;
    expect(s.vulnId, 'CVE-2024-1');
    expect(s.status, 'not_affected');
    expect(s.products, ['foo@1.0']);
    expect(s.justification, 'vulnerable_code_not_in_execute_path');
    expect(s.impactStatement, 'jamais appelé');
    expect(
      find.textContaining(
        'VEX : non affectée — code vulnérable jamais exécuté',
      ),
      findsOneWidget,
    );

    await tester.tap(find.text('Retirer'));
    await tester.pumpAndSettle();
    expect(vex.isEmpty, isTrue);
    expect(find.byKey(const Key('vex-declare')), findsOneWidget);
  });

  testWidgets('fiche CVE sans VexScope : aucune section VEX', (tester) async {
    await tester.pumpWidget(_app(const CveDetailPanel(detail: _detail)));
    expect(find.byKey(const Key('vex-declare')), findsNothing);
  });

  testWidgets('barre VEX : résumé, masquage, gestion', (tester) async {
    final vex = VexController()
      ..set(
        const VexStatement(
          vulnId: 'CVE-1',
          status: 'fixed',
          products: ['foo@1.0'],
        ),
      );
    var hide = true;
    await tester.pumpWidget(
      StatefulBuilder(
        builder: (context, setState) => _app(
          VexBar(
            controller: vex,
            hide: hide,
            onHideChanged: (v) => setState(() => hide = v),
            hiddenCount: 3,
          ),
        ),
      ),
    );
    expect(find.text('VEX : 1 déclaration'), findsOneWidget);
    expect(
      find.text('Masquer les CVE couvertes par un VEX (3)'),
      findsOneWidget,
    );
    await tester.tap(find.byKey(const Key('vex-hide')));
    await tester.pump();
    expect(hide, isFalse);

    await tester.tap(find.text('Gérer'));
    await tester.pumpAndSettle();
    expect(find.text('CVE-1'), findsOneWidget);
    await tester.tap(find.text('Tout retirer'));
    await tester.pumpAndSettle();
    expect(vex.isEmpty, isTrue);
    expect(find.text('VEX : 0 déclaration'), findsOneWidget);
  });
}
