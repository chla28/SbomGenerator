import 'dart:io';

import 'package:crypto/crypto.dart';
import 'dart:convert';

import 'scan_policy.dart' show Baseline;

/// Extensions des SBOM que `watch` retient dans un dossier.
const watchedSbomSuffixes = ['.cdx.json', '.spdx.json', '.spdx3.jsonld'];

/// Durée écrite `90s`, `30m`, `6h` ou `1d` ; lève [FormatException] sinon.
Duration parseWatchInterval(String text) {
  final m = RegExp(r'^(\d+)\s*([smhd])$').firstMatch(text.trim());
  if (m == null || int.parse(m.group(1)!) == 0) {
    throw FormatException(
        'durée invalide : "$text" (attendu : 90s, 30m, 6h, 1d)');
  }
  final n = int.parse(m.group(1)!);
  return switch (m.group(2)) {
    's' => Duration(seconds: n),
    'm' => Duration(minutes: n),
    'h' => Duration(hours: n),
    _ => Duration(days: n),
  };
}

/// SBOM désignés par [paths] : fichiers tels quels, dossiers parcourus
/// récursivement (liens ignorés). Triés pour un ordre de passage stable.
List<String> collectWatchedSboms(List<String> paths) {
  final out = <String>{};
  for (final p in paths) {
    if (FileSystemEntity.isDirectorySync(p)) {
      for (final e
          in Directory(p).listSync(recursive: true, followLinks: false)) {
        if (e is File && watchedSbomSuffixes.any(e.path.endsWith)) {
          out.add(e.path);
        }
      }
    } else {
      out.add(p);
    }
  }
  return out.toList()..sort();
}

/// Fichier d'état d'un SBOM : nom lisible + empreinte du chemin complet (deux
/// SBOM de même nom dans des dossiers différents ne se mélangent pas).
String watchStateFile(String stateDir, String sbomPath) {
  final name = sbomPath.split('/').last;
  final id = sha1.convert(utf8.encode(File(sbomPath).absolute.path)).toString();
  return '$stateDir/$name-${id.substring(0, 8)}.json';
}

/// Écart entre deux scans d'un même SBOM.
class WatchDiff {
  /// Constats présents maintenant et absents de l'état précédent.
  final List<Map<String, dynamic>> added;

  /// Nombre de constats de l'état précédent qui ont disparu (corrigés).
  final int resolved;

  /// Nombre de constats du scan courant.
  final int total;

  const WatchDiff(this.added, this.resolved, this.total);
}

/// Compare les `findings` de deux rapports `scan --format json`.
WatchDiff diffScans(
    Map<String, dynamic> previous, Map<String, dynamic> current) {
  List<Map<String, dynamic>> findings(Map<String, dynamic> r) => [
        for (final f in (r['findings'] as List? ?? const []))
          if (f is Map) f.cast<String, dynamic>(),
      ];
  final before = Baseline.fromJson(previous);
  final after = Baseline.fromJson(current);
  final now = findings(current);
  final added = [
    for (final f in now)
      if (!before.contains('${f['id']}', '${f['package']}')) f,
  ];
  final resolved = [
    for (final f in findings(previous))
      if (!after.contains('${f['id']}', '${f['package']}')) f,
  ];
  return WatchDiff(added, resolved.length, now.length);
}
