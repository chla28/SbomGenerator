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
    /// Cible à analyser : chemin d'un fichier SBOM (mode par défaut, sous-
    /// commande `sbom`), ou — si [useImage] est vrai — référence d'image de
    /// registre, ou chemin d'une archive/répertoire OCI local (sous-
    /// commande `image`).
    required String target,

    /// Analyse une image de conteneur (`trivy image`) plutôt qu'un fichier
    /// SBOM (`trivy sbom`).
    bool useImage = false,

    /// Valeur de --platform (ex. 'linux/arm64'), pertinente uniquement pour
    /// une image multi-architecture (ignorée si [useImage] est faux).
    String? platform,
    List<String> severities = const [],
    bool ignoreUnfixed = false,
    bool skipDbUpdate = false,
    String? configFile,
  }) {
    final controller = StreamController<TrivyEvent>();

    final args = buildArgs(
      target: target,
      useImage: useImage,
      platform: platform,
      severities: severities,
      ignoreUnfixed: ignoreUnfixed,
      skipDbUpdate: skipDbUpdate,
      configFile: configFile,
    );

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

  /// Arguments de `trivy` pour ces options — partagés par [run] et par
  /// l'aperçu « CLI Commande » de l'onglet.
  static List<String> buildArgs({
    required String target,
    bool useImage = false,
    String? platform,
    List<String> severities = const [],
    bool ignoreUnfixed = false,
    bool skipDbUpdate = false,
    String? configFile,
  }) {
    final args = <String>[useImage ? 'image' : 'sbom', '--format', 'json', '--quiet'];
    if (severities.isNotEmpty) {
      args.addAll(['--severity', severities.join(',')]);
    }
    if (ignoreUnfixed) args.add('--ignore-unfixed');
    if (skipDbUpdate) args.add('--skip-db-update');
    if (configFile != null && configFile.isNotEmpty) {
      args.addAll(['--config', configFile]);
    }
    if (useImage) {
      if (platform != null && platform.isNotEmpty) {
        args.addAll(['--platform', platform]);
      }
      // --input accepte aussi bien une archive (docker save / OCI) qu'un
      // répertoire OCI layout ; une référence de registre se passe en
      // argument positionnel classique.
      if (FileSystemEntity.typeSync(target) != FileSystemEntityType.notFound) {
        args.addAll(['--input', target]);
      } else {
        args.add(target);
      }
    } else {
      args.add(target);
    }
    return args;
  }

  void kill() {
    _process?.kill(ProcessSignal.sigterm);
    _process = null;
  }
}
