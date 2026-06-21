import 'dart:async';
import 'dart:convert';
import 'dart:io';

sealed class TrivyEvent {}

class TrivyOutputEvent extends TrivyEvent {
  final String jsonOutput;
  TrivyOutputEvent(this.jsonOutput);
}

class TrivyDoneEvent extends TrivyEvent {
  final int exitCode;
  final String? stderr;
  TrivyDoneEvent(this.exitCode, {this.stderr});
}

class TrivyRunner {
  Process? _process;
  bool get isRunning => _process != null;

  Stream<TrivyEvent> run({
    required String sbomFile,
    List<String> severities = const [],
    bool ignoreUnfixed = false,
    bool skipDbUpdate = false,
    String? configFile,
  }) {
    final controller = StreamController<TrivyEvent>();

    final args = ['sbom', '--format', 'json', '--quiet'];
    if (severities.isNotEmpty) {
      args.addAll(['--severity', severities.join(',')]);
    }
    if (ignoreUnfixed) args.add('--ignore-unfixed');
    if (skipDbUpdate) args.add('--skip-db-update');
    if (configFile != null && configFile.isNotEmpty) {
      args.addAll(['--config', configFile]);
    }
    args.add(sbomFile);

    final jsonBuf = StringBuffer();
    final stderrBuf = StringBuffer();

    Process.start('trivy', args).then((process) {
      _process = process;
      unawaited(process.stdin.close());

      process.stdout
          .transform(const Utf8Decoder(allowMalformed: true))
          .listen((c) {
        if (!controller.isClosed) jsonBuf.write(c);
      });

      process.stderr
          .transform(const Utf8Decoder(allowMalformed: true))
          .listen((c) {
        if (!controller.isClosed) stderrBuf.write(c);
      });

      process.exitCode.then((code) {
        _process = null;
        if (controller.isClosed) return;

        if (jsonBuf.isNotEmpty) {
          controller.add(TrivyOutputEvent(jsonBuf.toString()));
        }

        final stderr = stderrBuf.isNotEmpty ? stderrBuf.toString().trim() : null;
        controller.add(TrivyDoneEvent(code, stderr: code > 1 ? stderr : null));
        controller.close();
      });
    }).catchError((Object e) {
      _process = null;
      if (!controller.isClosed) {
        final msg = e.toString().contains('No such file')
            ? 'trivy introuvable — '
              'https://github.com/aquasecurity/trivy'
            : e.toString();
        controller.add(TrivyDoneEvent(127, stderr: msg));
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
