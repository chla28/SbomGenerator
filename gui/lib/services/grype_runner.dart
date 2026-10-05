import 'dart:async';
import 'dart:convert';
import 'dart:io';
import '../l10n/l10n.dart';

sealed class GrypeEvent {}

class GrypeOutputEvent extends GrypeEvent {
  final String jsonOutput;
  GrypeOutputEvent(this.jsonOutput);
}

class GrypeTemplateEvent extends GrypeEvent {
  final String content;
  GrypeTemplateEvent(this.content);
}

class GrypeDoneEvent extends GrypeEvent {
  final int exitCode;
  final String? stderr;
  GrypeDoneEvent(this.exitCode, {this.stderr});
}

class GrypeRunner {
  Process? _process;
  bool get isRunning => _process != null;

  Stream<GrypeEvent> run({
    /// Cible à analyser : chemin d'un fichier SBOM, ou — grype détecte
    /// automatiquement le type de source — référence d'image de registre
    /// (nginx:latest), chemin d'une archive (docker save / OCI) ou d'un
    /// répertoire OCI layout.
    required String target,
    String? failOn,
    bool onlyFixed = false,
    String? configFile,
    bool platformLinux = true,
    bool addCpesIfNone = true,
    bool byCve = true,
    String? distroVersion,
    String? templateFile,

    /// Valeur explicite de --platform (ex. 'linux/arm64'), utile pour une
    /// image multi-architecture. Prioritaire sur [platformLinux] si fournie.
    String? platform,
  }) {
    final controller = StreamController<GrypeEvent>();

    // Fichier temporaire pour la sortie template
    File? tmpFile;
    if (templateFile != null && templateFile.isNotEmpty) {
      tmpFile = File(
        '${Directory.systemTemp.path}/grype_tmpl_${DateTime.now().millisecondsSinceEpoch}.txt',
      );
    }

    final args = buildArgs(
      target: target,
      failOn: failOn,
      onlyFixed: onlyFixed,
      configFile: configFile,
      platformLinux: platformLinux,
      addCpesIfNone: addCpesIfNone,
      byCve: byCve,
      distroVersion: distroVersion,
      templateFile: templateFile,
      templateOutput: tmpFile?.path,
      platform: platform,
    );

    final jsonBuf = StringBuffer();
    final stderrBuf = StringBuffer();

    Process.start('grype', args)
        .then((process) {
          _process = process;
          unawaited(process.stdin.close());

          process.stdout
              .transform(const Utf8Decoder(allowMalformed: true))
              .listen((chunk) {
                if (!controller.isClosed) jsonBuf.write(chunk);
              });

          process.stderr
              .transform(const Utf8Decoder(allowMalformed: true))
              .listen((chunk) {
                if (!controller.isClosed) stderrBuf.write(chunk);
              });

          process.exitCode.then((code) async {
            _process = null;
            if (controller.isClosed) return;

            if (jsonBuf.isNotEmpty) {
              controller.add(GrypeOutputEvent(jsonBuf.toString()));
            }

            final tf = tmpFile;
            if (tf != null && tf.existsSync()) {
              try {
                final content = await tf.readAsString();
                if (!controller.isClosed && content.isNotEmpty) {
                  controller.add(GrypeTemplateEvent(content));
                }
              } catch (_) {}
              try {
                await tf.delete();
              } catch (_) {}
            }

            controller.add(
              GrypeDoneEvent(
                code,
                stderr: stderrBuf.isNotEmpty
                    ? stderrBuf.toString().trim()
                    : null,
              ),
            );
            controller.close();
          });
        })
        .catchError((Object e) {
          _process = null;
          if (!controller.isClosed) {
            final msg = e.toString().contains('No such file')
                ? appL10n().svcGrypeMissing
                : e.toString();
            controller.add(GrypeDoneEvent(1, stderr: msg));
            controller.close();
          }
        });

    return controller.stream;
  }

  /// Arguments de `grype` pour ces options — partagés par [run] et par
  /// l'aperçu « CLI Commande » des onglets. [templateOutput] : fichier de
  /// sortie du template (requis pour l'émettre avec [templateFile]).
  static List<String> buildArgs({
    required String target,
    String? failOn,
    bool onlyFixed = false,
    String? configFile,
    bool platformLinux = true,
    bool addCpesIfNone = true,
    bool byCve = true,
    String? distroVersion,
    String? templateFile,
    String? templateOutput,
    String? platform,
  }) {
    final args = <String>[target, '--output', 'json'];
    if (templateFile != null &&
        templateFile.isNotEmpty &&
        templateOutput != null) {
      args.addAll([
        '--output',
        'template=$templateOutput',
        '--template',
        templateFile,
      ]);
    }
    if (platform != null && platform.isNotEmpty) {
      args.addAll(['--platform', platform]);
    } else if (platformLinux) {
      args.addAll(['--platform', 'linux']);
    }
    if (addCpesIfNone) args.add('--add-cpes-if-none');
    if (byCve) args.add('--by-cve');
    if (distroVersion != null && distroVersion.isNotEmpty) {
      args.addAll(['--distro', 'rhel:$distroVersion']);
    }
    if (failOn != null && failOn.isNotEmpty) args.addAll(['--fail-on', failOn]);
    if (onlyFixed) args.add('--only-fixed');
    if (configFile != null && configFile.isNotEmpty) {
      args.addAll(['--config', configFile]);
    }
    return args;
  }

  void kill() {
    _process?.kill(ProcessSignal.sigterm);
    _process = null;
  }
}
