import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart' show visibleForTesting;

import '../l10n/l10n.dart';

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

    final jsonBuf = StringBuffer();
    final stderrBuf = StringBuffer();
    Directory? tmpDir;
    void cleanup() {
      final d = tmpDir;
      tmpDir = null;
      if (d != null) {
        try {
          d.deleteSync(recursive: true);
        } catch (_) {}
      }
    }

    // `osv-scanner scan image --archive` refuse un tar compressé (« invalid
    // tar header ») alors que grype et trivy l'acceptent : on lui passe une
    // copie décompressée, supprimée à la fin.
    _prepareTarget(target, useImage)
        .then((prepared) {
          tmpDir = prepared.tmpDir;
          final args = buildArgs(
            target: prepared.target,
            useImage: useImage,
            configFile: configFile,
          );
          return Process.start('osv-scanner', args);
        })
        .then((process) {
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
            cleanup();
            if (controller.isClosed) return;

            if (jsonBuf.isNotEmpty) {
              controller.add(OsvOutputEvent(jsonBuf.toString()));
            }

            // Exit 1 = vulnérabilités trouvées (normal), >1 = erreur réelle
            final stderr = stderrBuf.isNotEmpty
                ? stderrBuf.toString().trim()
                : null;
            controller.add(
              OsvDoneEvent(code, stderr: code > 1 ? stderr : null),
            );
            controller.close();
          });
        })
        .catchError((Object e) {
          _process = null;
          cleanup();
          if (!controller.isClosed) {
            final msg = e.toString().contains('No such file')
                ? appL10n().svcOsvMissing
                : e.toString();
            controller.add(OsvDoneEvent(127, stderr: msg));
            controller.close();
          }
        });

    return controller.stream;
  }

  /// `true` si [path] est un fichier gzip (octets magiques `1f 8b`), quelle
  /// que soit son extension (`.tar.gz`, `.tgz`…).
  static bool isGzipFile(String path) {
    try {
      final f = File(path);
      if (!f.existsSync()) return false;
      final raf = f.openSync();
      try {
        final head = raf.readSync(2);
        return head.length == 2 && head[0] == 0x1f && head[1] == 0x8b;
      } finally {
        raf.closeSync();
      }
    } catch (_) {
      return false;
    }
  }

  /// Cible effectivement passée à osv-scanner : pour une archive d'image
  /// locale compressée (gzip), une copie décompressée dans un dossier
  /// temporaire (à supprimer par l'appelant) ; sinon la cible inchangée.
  @visibleForTesting
  static Future<({String target, Directory? tmpDir})> prepareTarget(
    String target,
    bool useImage,
  ) => _prepareTarget(target, useImage);

  static Future<({String target, Directory? tmpDir})> _prepareTarget(
    String target,
    bool useImage,
  ) async {
    if (!useImage ||
        FileSystemEntity.typeSync(target) != FileSystemEntityType.file ||
        !isGzipFile(target)) {
      return (target: target, tmpDir: null);
    }
    final dir = await Directory.systemTemp.createTemp('osv_archive_');
    try {
      final out = File('${dir.path}/image.tar');
      final sink = out.openWrite();
      await sink.addStream(File(target).openRead().transform(gzip.decoder));
      await sink.close();
      return (target: out.path, tmpDir: dir);
    } catch (_) {
      dir.deleteSync(recursive: true);
      rethrow;
    }
  }

  /// Arguments d'`osv-scanner` pour ces options — partagés par [run] et par
  /// l'aperçu « CLI Commande » de l'onglet.
  static List<String> buildArgs({
    required String target,
    bool useImage = false,
    String? configFile,
  }) {
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

    return args;
  }

  void kill() {
    _process?.kill(ProcessSignal.sigterm);
    _process = null;
  }
}
