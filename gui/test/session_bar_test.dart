import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/scan_session.dart';
import 'package:sbom_generator_gui/services/session_store.dart';
import 'package:sbom_generator_gui/widgets/dashboard_panel.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/session_bar.dart';

GrypeVuln _g(String id, String sev) => GrypeVuln(
  id: id,
  severity: sev,
  packageName: 'pkg',
  installedVersion: '1.0',
  fixedVersion: '1.1',
  packageType: 'rpm',
);

ScanSession _s(DateTime at, List<GrypeVuln> g, {String target = 'SBOM a'}) =>
    ScanSession(savedAt: at, guiVersion: '1.7.0', targets: [target], grype: g);

Widget _app(Widget child) => MaterialApp(
  home: Scaffold(body: SingleChildScrollView(child: child)),
);

void main() {
  testWidgets('tableau de bord : barre de session et tendance', (tester) async {
    tester.view.physicalSize = const Size(1400, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final before = _s(DateTime(2026, 1, 1, 8), [
      _g('CVE-OLD', 'High'),
      _g('CVE-KEEP', 'Low'),
    ]);
    final current = _s(DateTime(2026, 2, 1), [
      _g('CVE-KEEP', 'Low'),
      _g('CVE-NEW', 'Critical'),
    ]);
    ScanSession? baseline = before;
    await tester.pumpWidget(
      StatefulBuilder(
        builder: (context, setState) => _app(
          SizedBox(
            height: 1300,
            child: DashboardPanel(
              grypeVulns: current.grype,
              osvVulns: null,
              trivyVulns: null,
              sessions: SessionActions(
                current: () => current,
                onLoad: (_) {},
                baseline: baseline,
                onBaseline: (b) => setState(() => baseline = b),
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('session-save')), findsOneWidget);
    expect(find.byKey(const Key('session-open')), findsOneWidget);
    expect(
      find.byKey(const Key('session-history')),
      findsNothing,
      reason: 'pas d\'historique sans store',
    );
    expect(find.byKey(const Key('trend-card')), findsOneWidget);
    expect(find.text('1 nouvelle(s)'), findsOneWidget);
    expect(find.text('1 disparue(s)'), findsOneWidget);
    expect(find.text('1 inchangée(s)'), findsOneWidget);
    expect(find.text('Total : 2 → 2'), findsOneWidget);
    expect(find.textContaining('CVE-NEW'), findsWidgets);

    await tester.tap(find.text('Retirer la comparaison'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('trend-card')), findsNothing);
  });

  testWidgets('historique : liste, ouverture et suppression', (tester) async {
    final tmp = Directory.systemTemp.createTempSync('hist_');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final store = SessionStore(tmp);
    await tester.runAsync(() async {
      await store.save(_s(DateTime(2026, 3, 1), [_g('CVE-1', 'High')]));
      await store.save(
        _s(DateTime(2026, 3, 2), [_g('CVE-2', 'Low')], target: 'image nginx'),
      );
    });

    final entries = (await tester.runAsync(store.list))!;
    ScanSession? opened;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () => showDialog<void>(
                context: context,
                builder: (_) => SessionHistoryDialog(
                  store: store,
                  initialEntries: Future.value(entries),
                  onOpen: (s) => opened = s,
                  onCompare: (_) {},
                ),
              ),
              child: const Text('go'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('go'));
    await tester.pump();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));

    expect(find.text('image nginx'), findsOneWidget);
    expect(find.text('SBOM a'), findsOneWidget);

    await tester.tap(find.text('Ouvrir').first);
    await tester.pump();
    expect(opened?.targets, ['image nginx'], reason: 'la plus récente en tête');
  });
}
