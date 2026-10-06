import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/services/scan_queue.dart';
import 'package:sbom_generator_gui/widgets/tasks_panel.dart';

void main() {
  testWidgets('file d\'attente : mise en file, annulation, échec et reprise', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final gate = Completer<void>();
    var osvAttempts = 0;
    final queue = ScanQueue((job, cancel) async {
      if (job.scanner == 'Grype') {
        cancel.onCancel(() {
          if (!gate.isCompleted) gate.complete();
        });
        await gate.future;
        return 4;
      }
      if (job.scanner == 'OSV-Scanner' && osvAttempts++ == 0) {
        throw ScanJobFailure('osv-scanner introuvable');
      }
      return 2;
    });

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: TasksPanel(
            queue: queue,
            outputFiles: const [OutputFile(path: '/tmp/x.cdx.json', size: '1')],
            onResult: (_) {},
          ),
        ),
      ),
    );

    // SBOM choisi automatiquement parmi les fichiers générés.
    expect(find.text('/tmp/x.cdx.json'), findsOneWidget);
    expect(find.text('Aucune analyse en file.'), findsOneWidget);

    await tester.tap(find.byKey(const Key('tasks-enqueue')));
    await tester.pump();
    expect(find.text('Grype · x.cdx.json'), findsOneWidget);
    expect(find.text('OSV-Scanner · x.cdx.json'), findsOneWidget);
    expect(find.text('Trivy · x.cdx.json'), findsOneWidget);
    expect(find.text('En attente'), findsNWidgets(2));
    expect(find.textContaining('En cours…'), findsOneWidget);

    // Annuler Grype (en cours) : la file enchaîne.
    await tester.tap(find.byTooltip('Annuler').first);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump();

    expect(
      find.textContaining('Échec : osv-scanner introuvable'),
      findsOneWidget,
    );
    expect(find.textContaining('Terminée — 2 vulnérabilités'), findsOneWidget);
    expect(find.textContaining('Annulée'), findsOneWidget);

    // Reprise de l'analyse OSV échouée.
    await tester.tap(find.byTooltip('Relancer').last);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    expect(find.textContaining('Échec'), findsNothing);

    // Purge des analyses terminées.
    await tester.tap(find.text('Retirer les terminées'));
    await tester.pump();
    expect(find.text('Trivy · x.cdx.json'), findsNothing);
    queue.dispose();
  });

  testWidgets('aucun scanner coché : message, rien en file', (tester) async {
    final queue = ScanQueue((job, cancel) async => 0);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: TasksPanel(
            queue: queue,
            outputFiles: const [OutputFile(path: '/tmp/x.cdx.json', size: '1')],
            onResult: (_) {},
          ),
        ),
      ),
    );
    for (final s in ['Grype', 'OSV-Scanner', 'Trivy']) {
      await tester.tap(find.byKey(Key('tasks-scanner-$s')));
    }
    await tester.pump();
    await tester.tap(find.byKey(const Key('tasks-enqueue')));
    await tester.pump();
    expect(find.text('Cochez au moins un scanner.'), findsOneWidget);
    expect(queue.jobs, isEmpty);
    queue.dispose();
  });
}
