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
    /// Cible à analyser : chemin d'un fichier SBOM (mode par défaut), ou —
    /// si [useImage] est vrai — référence d'image de registre ou chemin
    /// d'une archive locale (docker save / OCI).
    required String target,

    /// Analyse une image de conteneur (`osv-scanner scan image`) plutôt
    /// qu'un fichier SBOM (ancien style `--sbom`, conservé tel quel pour ne
    /// pas changer le comportement existant).
    bool useImage = false,
    String? configFile,
  }) {
    final controller = StreamController<OsvEvent>();

    final args = <String>[];
    if (useImage) {
      // `scan image` est la seule sous-commande d'osv-scanner qui sache
      // analyser une image de conteneur ; elle n'existe pas dans l'ancien
      // style de commande utilisé ci-dessous pour les fichiers SBOM.
      // --archive n'accepte qu'une archive locale (tar) ; un répertoire OCI
      // layout n'est pas géré par osv-scanner, on passe donc la cible telle
      // quelle dans ce cas (osv-scanner rapportera son propre message
      // d'erreur si ce n'est pas supporté).
      args.addAll(['scan', 'image', '--format', 'json']);
      if (FileSystemEntity.typeSync(target) == FileSystemEntityType.file) {
        args.addAll(['--archive', target]);
      } else {
        args.add(target);
      }
    } else {
      args.addAll(['--format', 'json', '--sbom', target]);
    }
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
