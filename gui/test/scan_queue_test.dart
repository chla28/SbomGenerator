import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/services/scan_queue.dart';

void main() {
  test('exécution séquentielle dans l\'ordre d\'ajout', () async {
    final order = <String>[];
    var running = 0, maxRunning = 0;
    final q = ScanQueue((job, cancel) async {
      running++;
      maxRunning = running > maxRunning ? running : maxRunning;
      order.add('${job.scanner}:${job.target}');
      await Future<void>.delayed(const Duration(milliseconds: 5));
      running--;
      return job.id * 10;
    });
    q.add('grype', 'a');
    q.add('osv', 'a');
    q.add('trivy', 'b');
    await q.waitIdle();
    expect(order, ['grype:a', 'osv:a', 'trivy:b']);
    expect(maxRunning, 1);
    expect(q.jobs.map((j) => j.status), everyElement(ScanJobStatus.done));
    expect(q.jobs.map((j) => j.findings), [10, 20, 30]);
    expect(q.isBusy, isFalse);
  });

  test(
    'échec : message conservé, la file continue ; reprise possible',
    () async {
      var attempts = 0;
      final q = ScanQueue((job, cancel) async {
        if (job.scanner == 'osv' && attempts++ == 0) {
          throw ScanJobFailure('osv-scanner introuvable');
        }
        return 1;
      });
      q.add('osv', 'a');
      q.add('grype', 'a');
      await q.waitIdle();
      expect(q.jobs[0].status, ScanJobStatus.failed);
      expect(q.jobs[0].error, 'osv-scanner introuvable');
      expect(q.jobs[1].status, ScanJobStatus.done);

      q.retry(q.jobs[0].id);
      await q.waitIdle();
      expect(q.jobs[0].status, ScanJobStatus.done);
      expect(q.jobs[0].error, isNull);
    },
  );

  test('annulation d\'une analyse en attente', () async {
    final gate = Completer<void>();
    final started = <int>[];
    final q = ScanQueue((job, cancel) async {
      started.add(job.id);
      await gate.future;
      return 0;
    });
    final a = q.add('grype', 'a');
    final b = q.add('osv', 'a');
    await Future<void>.delayed(Duration.zero);
    expect(a.status, ScanJobStatus.running);
    expect(b.status, ScanJobStatus.queued);
    q.cancel(b.id);
    expect(b.status, ScanJobStatus.cancelled);
    gate.complete();
    await q.waitIdle();
    expect(started, [a.id], reason: 'l\'analyse annulée n\'est jamais lancée');
  });

  test(
    'annulation d\'une analyse en cours : le crochet arrête le processus',
    () async {
      var killed = false;
      final q = ScanQueue((job, cancel) {
        final done = Completer<int>();
        cancel.onCancel(() {
          killed = true;
          done.complete(0); // le processus se termine après kill
        });
        return done.future;
      });
      final j = q.add('trivy', 'a');
      await Future<void>.delayed(Duration.zero);
      expect(j.status, ScanJobStatus.running);
      q.cancel(j.id);
      await q.waitIdle();
      expect(killed, isTrue);
      expect(j.status, ScanJobStatus.cancelled);
      expect(j.findings, isNull);
      q.retry(j.id);
      expect(j.status, anyOf(ScanJobStatus.queued, ScanJobStatus.running));
      q.cancelAll();
      await q.waitIdle();
    },
  );

  test('remove / clearFinished : jamais l\'analyse en cours', () async {
    final gate = Completer<void>();
    final q = ScanQueue((job, cancel) async {
      await gate.future;
      return 0;
    });
    final a = q.add('grype', 'a');
    final b = q.add('osv', 'a');
    await Future<void>.delayed(Duration.zero);
    q.remove(a.id); // en cours : refusé
    expect(q.jobs, hasLength(2));
    q.remove(b.id); // en attente : retirée
    expect(q.jobs, hasLength(1));
    gate.complete();
    await q.waitIdle();
    q.clearFinished();
    expect(q.jobs, isEmpty);
  });

  test('notifie les écouteurs à chaque changement d\'état', () async {
    final q = ScanQueue((job, cancel) async => 2);
    var n = 0;
    q.addListener(() => n++);
    q.add('grype', 'a');
    await q.waitIdle();
    expect(n, greaterThanOrEqualTo(3)); // ajout, démarrage, fin
  });
}
