import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../models/sbom_result.dart';
import 'settings_service.dart';
import '../l10n/l10n.dart';

// ─── Événements de progression ───────────────────────────────────────────────

sealed class SbomEvent {}

/// Ligne de progression parsée depuis stdout.
class SbomProgressEvent extends SbomEvent {
  final int current;
  final int total;
  final int percent;
  final String label;
  SbomProgressEvent({
    required this.current,
    required this.total,
    required this.percent,
    required this.label,
  });
}

/// Ligne de log générique (stdout ou stderr).
class SbomLogEvent extends SbomEvent {
  final String line;
  final bool isError;
  final bool isWarning;
  SbomLogEvent(this.line, {this.isError = false, this.isWarning = false});
}

/// Fichier SBOM généré (parsé depuis "SBOM written → ...").
class SbomOutputFileEvent extends SbomEvent {
  final OutputFile file;
  SbomOutputFileEvent(this.file);
}

/// Fin du processus.
class SbomDoneEvent extends SbomEvent {
  final int exitCode;
  SbomDoneEvent(this.exitCode);
}

// ─── Regex de parsing stdout ─────────────────────────────────────────────────

// "  [████░░░░] 12/23  52%  package-name"
final _progressRe = RegExp(r'\]\s+(\d+)/(\d+)\s+(\d+)%\s+(.*)$');

// "SBOM written → sbom.cdx.json  (542.3 KB)"
final _outputFileRe = RegExp(r'SBOM written\s*→\s*(.+?)\s+\((.+?)\)');

// ─── Runner ──────────────────────────────────────────────────────────────────

class SbomRunner {
  Process? _process;

  bool get isRunning => _process != null;

  static String get _cli => SettingsService.cliBinary;

  Stream<SbomEvent> run({required List<String> args}) {
    final controller = StreamController<SbomEvent>();

    Process.start(_cli, args, environment: SettingsService.cliEnvironment)
        .then((process) {
          _process = process;
          unawaited(process.stdin.close());

          // STDOUT : progression + "SBOM written → …"
          process.stdout
              .transform(const Utf8Decoder(allowMalformed: true))
              .transform(const LineSplitter())
              .listen((line) {
                if (controller.isClosed) return;

                final progressMatch = _progressRe.firstMatch(line);
                if (progressMatch != null) {
                  controller.add(
                    SbomProgressEvent(
                      current: int.parse(progressMatch.group(1)!),
                      total: int.parse(progressMatch.group(2)!),
                      percent: int.parse(progressMatch.group(3)!),
                      label: progressMatch.group(4)!.trim(),
                    ),
                  );
                  return;
                }

                final outputMatch = _outputFileRe.firstMatch(line);
                if (outputMatch != null) {
                  controller.add(
                    SbomOutputFileEvent(
                      OutputFile(
                        path: outputMatch.group(1)!.trim(),
                        size: outputMatch.group(2)!.trim(),
                      ),
                    ),
                  );
                }

                controller.add(SbomLogEvent(line));
              });

          // STDERR : warnings + erreurs
          process.stderr
              .transform(const Utf8Decoder(allowMalformed: true))
              .transform(const LineSplitter())
              .listen((line) {
                if (controller.isClosed) return;
                final isError = line.startsWith('Error:');
                final isWarning =
                    line.startsWith('Warning:') ||
                    line.startsWith('⚠') ||
                    line.startsWith('   •');
                controller.add(
                  SbomLogEvent(line, isError: isError, isWarning: isWarning),
                );
              });

          process.exitCode.then((code) {
            _process = null;
            if (!controller.isClosed) {
              controller.add(SbomDoneEvent(code));
              controller.close();
            }
          });
        })
        .catchError((Object e) {
          _process = null;
          if (!controller.isClosed) {
            controller.add(
              SbomLogEvent(appL10n().svcLaunchError('$e'), isError: true),
            );
            controller.add(SbomDoneEvent(1));
            controller.close();
          }
        });

    return controller.stream;
  }

  void kill() {
    _process?.kill(ProcessSignal.sigterm);
    _process = null;
  }
}
