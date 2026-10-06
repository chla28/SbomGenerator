import 'dart:async';

import 'package:flutter/foundation.dart';

enum ScanJobStatus { queued, running, done, failed, cancelled }

/// Une analyse en file d'attente : un scanner sur une cible (fichier SBOM).
class ScanJob {
  final int id;
  final String scanner;
  final String target;
  ScanJobStatus status = ScanJobStatus.queued;
  DateTime? startedAt;
  DateTime? finishedAt;

  /// Message d'erreur (statut `failed`).
  String? error;

  /// Nombre de vulnérabilités trouvées (statut `done`).
  int? findings;

  ScanJob(this.id, this.scanner, this.target);

  bool get isFinished =>
      status == ScanJobStatus.done ||
      status == ScanJobStatus.failed ||
      status == ScanJobStatus.cancelled;

  Duration? get duration => startedAt == null
      ? null
      : (finishedAt ?? DateTime.now()).difference(startedAt!);
}

/// Jeton d'annulation d'une analyse en cours : l'exécuteur y branche l'arrêt
/// de son processus.
class JobCancel {
  bool _cancelled = false;
  VoidCallback? _hook;
  bool get isCancelled => _cancelled;

  /// Appelé (une fois) quand l'annulation est demandée — immédiatement si elle
  /// l'est déjà.
  void onCancel(VoidCallback hook) {
    _hook = hook;
    if (_cancelled) hook();
  }

  void cancel() {
    if (_cancelled) return;
    _cancelled = true;
    _hook?.call();
  }
}

/// Échec d'une analyse (message affiché à l'utilisateur).
class ScanJobFailure implements Exception {
  final String message;
  ScanJobFailure(this.message);
  @override
  String toString() => message;
}

/// Exécute une analyse ; retourne le nombre de vulnérabilités trouvées, lève
/// [ScanJobFailure] en cas d'échec.
typedef ScanJobExecutor = Future<int> Function(ScanJob job, JobCancel cancel);

/// File d'attente d'analyses exécutées **une à une** (les scanners sont
/// gourmands et partagent leur base de vulnérabilités). Annulation, reprise
/// des analyses échouées ou annulées, purge des analyses terminées.
class ScanQueue extends ChangeNotifier {
  final ScanJobExecutor _executor;
  final List<ScanJob> _jobs = [];
  final Map<int, JobCancel> _cancels = {};
  int _nextId = 1;
  bool _pumping = false;
  Completer<void>? _idle;

  ScanQueue(this._executor);

  List<ScanJob> get jobs => List.unmodifiable(_jobs);

  bool get isBusy => _jobs.any(
    (j) =>
        j.status == ScanJobStatus.queued || j.status == ScanJobStatus.running,
  );

  int get queuedCount =>
      _jobs.where((j) => j.status == ScanJobStatus.queued).length;

  ScanJob add(String scanner, String target) {
    final job = ScanJob(_nextId++, scanner, target);
    _jobs.add(job);
    notifyListeners();
    _pump();
    return job;
  }

  /// Annule une analyse : immédiatement si elle attend, en arrêtant le
  /// processus si elle tourne.
  void cancel(int id) {
    final job = _byId(id);
    if (job == null) return;
    if (job.status == ScanJobStatus.queued) {
      job
        ..status = ScanJobStatus.cancelled
        ..finishedAt = DateTime.now();
      notifyListeners();
    } else if (job.status == ScanJobStatus.running) {
      _cancels[id]?.cancel();
    }
  }

  /// Annule tout : les analyses en attente et celle en cours.
  void cancelAll() {
    for (final j in List.of(_jobs)) {
      cancel(j.id);
    }
  }

  /// Remet en file une analyse échouée ou annulée.
  void retry(int id) {
    final job = _byId(id);
    if (job == null ||
        !(job.status == ScanJobStatus.failed ||
            job.status == ScanJobStatus.cancelled)) {
      return;
    }
    job
      ..status = ScanJobStatus.queued
      ..error = null
      ..findings = null
      ..startedAt = null
      ..finishedAt = null;
    notifyListeners();
    _pump();
  }

  /// Retire une analyse qui ne tourne pas.
  void remove(int id) {
    final job = _byId(id);
    if (job == null || job.status == ScanJobStatus.running) return;
    _jobs.remove(job);
    notifyListeners();
  }

  void clearFinished() {
    _jobs.removeWhere((j) => j.isFinished);
    notifyListeners();
  }

  /// Se termine quand plus rien n'est en attente ni en cours.
  Future<void> waitIdle() {
    if (!isBusy && !_pumping) return Future.value();
    return (_idle ??= Completer<void>()).future;
  }

  ScanJob? _byId(int id) {
    for (final j in _jobs) {
      if (j.id == id) return j;
    }
    return null;
  }

  Future<void> _pump() async {
    if (_pumping) return;
    _pumping = true;
    try {
      while (true) {
        final next = _jobs
            .where((j) => j.status == ScanJobStatus.queued)
            .firstOrNull;
        if (next == null) break;
        final cancel = _cancels[next.id] = JobCancel();
        next
          ..status = ScanJobStatus.running
          ..startedAt = DateTime.now();
        notifyListeners();
        try {
          final n = await _executor(next, cancel);
          if (cancel.isCancelled) {
            next.status = ScanJobStatus.cancelled;
          } else {
            next
              ..status = ScanJobStatus.done
              ..findings = n;
          }
        } on ScanJobFailure catch (e) {
          next
            ..status = cancel.isCancelled
                ? ScanJobStatus.cancelled
                : ScanJobStatus.failed
            ..error = e.message;
        } catch (e) {
          next
            ..status = cancel.isCancelled
                ? ScanJobStatus.cancelled
                : ScanJobStatus.failed
            ..error = '$e';
        }
        next.finishedAt = DateTime.now();
        _cancels.remove(next.id);
        notifyListeners();
      }
    } finally {
      _pumping = false;
      if (!isBusy) {
        _idle?.complete();
        _idle = null;
      }
    }
  }
}
