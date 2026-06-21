import 'dart:async';
import 'dart:convert';
import 'dart:io';

sealed class OsvEvent {}

class OsvOutputEvent extends OsvEvent {
  final String jsonOutput;
  OsvOutputEvent(this.jsonOutput);
}

class OsvDoneEvent extends OsvEvent {
  final int exitCode;
  final String? stderr;
  OsvDoneEvent(this.exitCode, {this.stderr});
}

class OsvRunner {
  Process? _process;
  bool get isRunning => _process != null;

  Stream<OsvEvent> run({
    required String sbomFile,
    String? configFile,
  }) {
    final controller = StreamController<OsvEvent>();

    final args = ['--format', 'json', '--sbom', sbomFile];
    if (configFile != null && configFile.isNotEmpty) {
      args.addAll(['--config', configFile]);
    }

    final jsonBuf = StringBuffer();
    final stderrBuf = StringBuffer();

    Process.start('osv-scanner', args).then((process) {
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
          controller.add(OsvOutputEvent(jsonBuf.toString()));
        }

        // Exit 1 = vulnérabilités trouvées (normal), >1 = erreur réelle
        final stderr = stderrBuf.isNotEmpty ? stderrBuf.toString().trim() : null;
        controller.add(OsvDoneEvent(code, stderr: code > 1 ? stderr : null));
        controller.close();
      });
    }).catchError((Object e) {
      _process = null;
      if (!controller.isClosed) {
        final msg = e.toString().contains('No such file')
            ? 'osv-scanner introuvable — '
              'https://github.com/google/osv-scanner'
            : e.toString();
        controller.add(OsvDoneEvent(127, stderr: msg));
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
