import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'i18n.dart';

/// Fichiers du cache d'enrichissement qu'un bundle peut transporter.
const offlineCacheFiles = ['kev.json', 'epss.json', 'poc.json'];

const _bundleFormat = 'sbom-generator-offline/v1';

class OfflineException implements Exception {
  final String message;
  OfflineException(this.message);
  @override
  String toString() => message;
}

class CacheFileInfo {
  final String name;
  final int bytes;
  final int entries;
  final DateTime modified;
  const CacheFileInfo(this.name, this.bytes, this.entries, this.modified);
}

/// État des fichiers présents dans [cacheDir].
List<CacheFileInfo> cacheStatus(Directory cacheDir) => [
      for (final name in offlineCacheFiles)
        if (File('${cacheDir.path}/$name').existsSync())
          () {
            final f = File('${cacheDir.path}/$name');
            return CacheFileInfo(
                name, f.lengthSync(), _entryCount(f), f.lastModifiedSync());
          }(),
    ];

int _entryCount(File f) {
  try {
    final d = jsonDecode(f.readAsStringSync());
    if (d is! Map) return 0;
    // kev.json range les CVE sous « cves » ; les autres sont indexés par CVE.
    return d['cves'] is Map ? (d['cves'] as Map).length : d.length;
  } catch (_) {
    return 0;
  }
}

String _sha256(String s) => sha256.convert(utf8.encode(s)).toString();

/// Écrit dans [outPath] un bundle gzip (JSON) contenant le cache de
/// [cacheDir]. Renvoie les noms de fichiers inclus.
List<String> exportOfflineBundle(Directory cacheDir, String outPath) {
  final files = <String, dynamic>{};
  for (final name in offlineCacheFiles) {
    final f = File('${cacheDir.path}/$name');
    if (!f.existsSync()) continue;
    final content = f.readAsStringSync();
    files[name] = {'sha256': _sha256(content), 'content': content};
  }
  if (!files.containsKey('kev.json')) {
    throw OfflineException(tr(
        'cache vide : lancer d\'abord « offline prepare » (ou un scan en ligne)'));
  }
  final doc = {
    'format': _bundleFormat,
    'createdAt': DateTime.now().toUtc().toIso8601String(),
    'files': files,
  };
  File(outPath).writeAsBytesSync(gzip.encode(utf8.encode(jsonEncode(doc))));
  return files.keys.toList();
}

/// Importe [bundlePath] dans [cacheDir]. KEV est remplacé s'il est plus
/// récent ; EPSS et PoC (indexés par CVE) sont fusionnés, l'entrée la plus
/// récente gagne. Renvoie les noms de fichiers mis à jour.
List<String> importOfflineBundle(String bundlePath, Directory cacheDir) {
  final Map<String, dynamic> doc;
  try {
    doc =
        jsonDecode(utf8.decode(gzip.decode(File(bundlePath).readAsBytesSync())))
            as Map<String, dynamic>;
  } catch (_) {
    throw OfflineException(
        tr('bundle illisible : {path}', {'path': bundlePath}));
  }
  if (doc['format'] != _bundleFormat || doc['files'] is! Map) {
    throw OfflineException(tr('format de bundle inconnu'));
  }
  final files = (doc['files'] as Map).cast<String, dynamic>();
  // Contrôle de tout le bundle avant la moindre écriture.
  for (final e in files.entries) {
    if (!offlineCacheFiles.contains(e.key)) {
      throw OfflineException(
          tr('fichier inattendu dans le bundle : {name}', {'name': e.key}));
    }
    final content = (e.value as Map)['content'];
    if (content is! String || _sha256(content) != (e.value as Map)['sha256']) {
      throw OfflineException(tr(
          'empreinte invalide pour {name} : bundle altéré', {'name': e.key}));
    }
    try {
      if (jsonDecode(content) is! Map) throw const FormatException('');
    } on FormatException {
      throw OfflineException(
          tr('contenu invalide pour {name}', {'name': e.key}));
    }
  }

  cacheDir.createSync(recursive: true);
  final updated = <String>[];
  for (final e in files.entries) {
    final incoming = jsonDecode((e.value as Map)['content'] as String)
        as Map<String, dynamic>;
    final target = File('${cacheDir.path}/${e.key}');
    Map<String, dynamic> result = incoming;
    if (target.existsSync()) {
      Map<String, dynamic>? local;
      try {
        local = jsonDecode(target.readAsStringSync()) as Map<String, dynamic>;
      } catch (_) {}
      if (local != null) {
        result = e.key == 'kev.json'
            ? (_stamp(incoming).isBefore(_stamp(local)) ? local : incoming)
            : _mergeByCve(local, incoming);
      }
    }
    final tmp = File('${target.path}.tmp')
      ..writeAsStringSync(jsonEncode(result));
    tmp.renameSync(target.path);
    updated.add(e.key);
  }
  return updated;
}

DateTime _stamp(Map<String, dynamic> m) =>
    DateTime.tryParse('${m['fetchedAt']}') ??
    DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

Map<String, dynamic> _mergeByCve(
    Map<String, dynamic> local, Map<String, dynamic> incoming) {
  final out = {...local};
  for (final e in incoming.entries) {
    final cur = out[e.key];
    if (cur is! Map ||
        e.value is! Map ||
        !_stamp((e.value as Map).cast<String, dynamic>())
            .isBefore(_stamp(cur.cast<String, dynamic>()))) {
      out[e.key] = e.value;
    }
  }
  return out;
}
