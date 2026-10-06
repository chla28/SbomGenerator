import 'dart:async';

import '../l10n/l10n.dart';
import '../widgets/grype_panel.dart';
import '../widgets/osv_panel.dart';
import '../widgets/trivy_panel.dart';
import '../widgets/vuln_shared.dart' show dedupeVulns;
import 'grype_runner.dart';
import 'osv_runner.dart';
import 'scan_enrichment.dart';
import 'scan_queue.dart';
import 'trivy_runner.dart';

/// Noms des scanners tels qu'affichés et portés par [ScanJob.scanner].
const kScanners = ['Grype', 'OSV-Scanner', 'Trivy'];

/// Résultat d'une analyse de la file, remis au tableau de bord.
class ScanJobResult {
  final String scanner;

  /// Libellé de la cible (« SBOM x.cdx.json »).
  final String target;
  final List<GrypeVuln>? grype;
  final List<OsvVuln>? osv;
  final List<TrivyVuln>? trivy;
  final Map<String, ExploitInfo> exploit;

  const ScanJobResult({
    required this.scanner,
    required this.target,
    this.grype,
    this.osv,
    this.trivy,
    this.exploit = const {},
  });
}

/// Exécuteur de [ScanQueue] : lance le scanner sur le SBOM, analyse la sortie
/// JSON, enrichit (KEV/EPSS/PoC) et remet le résultat à [onResult].
ScanJobExecutor makeScanJobExecutor({
  required void Function(ScanJobResult) onResult,
  required Future<bool> Function() enrichOnline,
}) {
  return (job, cancel) async {
    final l = appL10n();
    final label = l.scanTargetSbom(job.target.split(RegExp(r'[/\\]')).last);

    String? json;
    int? code;
    String? err;
    Stream<Object> events;
    void Function() kill;
    switch (job.scanner) {
      case 'Grype':
        final r = GrypeRunner();
        kill = r.kill;
        events = r.run(target: job.target);
      case 'OSV-Scanner':
        final r = OsvRunner();
        kill = r.kill;
        events = r.run(target: job.target);
      case 'Trivy':
        final r = TrivyRunner();
        kill = r.kill;
        events = r.run(target: job.target);
      default:
        throw ScanJobFailure('${job.scanner}?');
    }
    cancel.onCancel(kill);
    await for (final e in events) {
      switch (e) {
        case GrypeOutputEvent(:final jsonOutput):
          json = jsonOutput;
        case GrypeDoneEvent(:final exitCode, :final stderr):
          code = exitCode;
          err = stderr;
        case OsvOutputEvent(:final jsonOutput):
          json = jsonOutput;
        case OsvDoneEvent(:final exitCode, :final stderr):
          code = exitCode;
          err = stderr;
        case TrivyOutputEvent(:final jsonOutput):
          json = jsonOutput;
        case TrivyDoneEvent(:final exitCode, :final stderr):
          code = exitCode;
          err = stderr;
        default:
          break;
      }
    }
    if (cancel.isCancelled) throw ScanJobFailure('cancelled');
    if (json == null || json.trim().isEmpty) {
      if (code == 127) throw ScanJobFailure(l.tasksToolMissing(job.scanner));
      throw ScanJobFailure(
        l.tasksNoOutput(job.scanner, code ?? -1, (err ?? '').trim()),
      );
    }

    final online = await enrichOnline();
    try {
      switch (job.scanner) {
        case 'Grype':
          final v = dedupeVulns(
            GrypeVuln.fromJson(json),
            (x, n) => x.withOccurrenceCount(n),
          );
          final ex = await _enrich(
            v.map((x) => x.id),
            seedsFromGrypeJson(json),
            online,
          );
          onResult(
            ScanJobResult(
              scanner: job.scanner,
              target: label,
              grype: v,
              exploit: ex,
            ),
          );
          return v.length;
        case 'OSV-Scanner':
          final v = dedupeVulns(
            OsvVuln.fromJson(json),
            (x, n) => x.withOccurrenceCount(n),
          );
          final ex = await _enrich(
            v.map((x) => x.id),
            seedsFromOsvJson(json),
            online,
          );
          onResult(
            ScanJobResult(
              scanner: job.scanner,
              target: label,
              osv: v,
              exploit: ex,
            ),
          );
          return v.length;
        default:
          final v = dedupeVulns(
            TrivyVuln.fromJson(json),
            (x, n) => x.withOccurrenceCount(n),
          );
          final ex = await _enrich(
            v.map((x) => x.id),
            seedsFromTrivyJson(json),
            online,
          );
          onResult(
            ScanJobResult(
              scanner: job.scanner,
              target: label,
              trivy: v,
              exploit: ex,
            ),
          );
          return v.length;
      }
    } on FormatException catch (e) {
      throw ScanJobFailure(l.tasksParseFailed(job.scanner, e.message));
    }
  };
}

Future<Map<String, ExploitInfo>> _enrich(
  Iterable<String> ids,
  Map<String, CveSeed> seed,
  bool online,
) async {
  try {
    return await enrichCves(
      ids.map(normalizeCveId).toSet(),
      seed: seed,
      online: online,
    );
  } catch (_) {
    return const {}; // l'enrichissement est facultatif
  }
}
