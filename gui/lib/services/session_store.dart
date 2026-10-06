import 'dart:io';

import '../models/scan_session.dart';

/// Une session de l'historique (métadonnées lues dans le fichier).
class SessionEntry {
  final File file;
  final ScanSession session;
  const SessionEntry(this.file, this.session);
}

/// Historique des analyses : un fichier JSON par (cibles, jour) dans [dir].
/// Une nouvelle analyse de la même cible le même jour remplace l'entrée ;
/// au-delà de [maxEntries], les plus anciennes sont supprimées.
class SessionStore {
  final Directory dir;
  final int maxEntries;
  SessionStore(this.dir, {this.maxEntries = 50});

  /// `$XDG_DATA_HOME/sbom-generator-gui/history` (`~/.local/share/…`).
  static Directory defaultDir() {
    final env = Platform.environment;
    final base =
        env['XDG_DATA_HOME'] ??
        (env['HOME'] != null
            ? '${env['HOME']}/.local/share'
            : Directory.systemTemp.path);
    return Directory('$base/sbom-generator-gui/history');
  }

  static String _fnv(String s) {
    var h = 0x811c9dc5;
    for (final c in s.codeUnits) {
      h = ((h ^ c) * 0x01000193) & 0xffffffff;
    }
    return h.toRadixString(16).padLeft(8, '0');
  }

  /// Nom de fichier stable : date locale du jour + empreinte des cibles.
  static String fileNameFor(ScanSession s) {
    final d = s.savedAt.toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    final targets = [...s.targets]..sort();
    return 'session-${d.year}${two(d.month)}${two(d.day)}-'
        '${_fnv(targets.join('\n'))}.json';
  }

  Future<File> save(ScanSession session) async {
    await dir.create(recursive: true);
    final file = File('${dir.path}/${fileNameFor(session)}');
    await file.writeAsString(session.encode());
    await _prune();
    return file;
  }

  /// Sessions lisibles, la plus récente d'abord ; les fichiers illisibles sont
  /// ignorés.
  Future<List<SessionEntry>> list() async {
    if (!await dir.exists()) return const [];
    final out = <SessionEntry>[];
    await for (final e in dir.list()) {
      if (e is! File || !e.path.endsWith('.json')) continue;
      try {
        out.add(SessionEntry(e, ScanSession.decode(await e.readAsString())));
      } catch (_) {}
    }
    out.sort((a, b) => b.session.savedAt.compareTo(a.session.savedAt));
    return out;
  }

  Future<ScanSession> load(File f) async =>
      ScanSession.decode(await f.readAsString());

  Future<void> delete(File f) async {
    if (await f.exists()) await f.delete();
  }

  Future<void> clear() async {
    for (final e in await list()) {
      await e.file.delete();
    }
  }

  Future<void> _prune() async {
    final all = await list();
    for (final e in all.skip(maxEntries)) {
      await e.file.delete();
    }
  }
}
