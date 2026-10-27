import 'dart:io';
import 'hash_utils.dart' show packageHash;
import 'models.dart';
import 'i18n.dart';

/// Parses les lockfiles Python TOML : `uv.lock`, `poetry.lock`, `pdm.lock`.
///
/// Les trois utilisent des blocs `[[package]]` avec `name` et `version`. Les
/// paquets locaux (projet lui-même, dépendances `path`/éditables) ne sont pas
/// des composants tiers et sont écartés. Un lockfile liste plusieurs fichiers
/// (roues, sdist) par paquet : seule l'empreinte de l'archive source (sdist)
/// est retenue, car c'est la seule non ambiguë.
class PythonLockParser {
  List<WheelPackage> parseLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('lockfile Python introuvable : {path}', {'path': path}));
      return [];
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    Map<String, String>? block;
    var sdistHash = '';
    var local = false;

    void flush() {
      final b = block;
      block = null;
      final sdist = sdistHash;
      final isLocal = local;
      sdistHash = '';
      local = false;
      if (b == null || isLocal) return;
      final name = b['name'] ?? '';
      final version = b['version'] ?? '';
      if (name.isEmpty || version.isEmpty) return;
      if (!seen.add('${name.toLowerCase()}@$version')) return;
      final hash = packageHash('SHA-256', sdist);
      packages.add(WheelPackage(
        name: name,
        version: version,
        license: '',
        url: 'https://pypi.org/project/$name/$version/',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        hashes: [if (hash != null) hash],
        requires: [],
        provides: [name],
        packageType: 'pypi',
      ));
    }

    final kv = RegExp(r'^(\w+)\s*=\s*"(.*)"\s*$');
    final sdistFile =
        RegExp(r'"[^"]+\.tar\.gz"[^}]*?hash\s*=\s*"sha256:([0-9a-f]{64})"');
    // uv : source = { editable = "." } | { virtual = "." } | { directory = … }
    // poetry : [package.source] type = "directory" | "file"
    final localSource =
        RegExp(r'^source\s*=\s*\{\s*(editable|virtual|directory|path)\b');
    var inSource = false;
    var inSubTable = false;
    for (final raw in file.readAsLinesSync()) {
      final line = raw.trim();
      if (line == '[[package]]') {
        flush();
        block = {};
        inSource = false;
        inSubTable = false;
        continue;
      }
      if (line.startsWith('[')) {
        inSource = line == '[package.source]';
        inSubTable = true;
        continue;
      }
      if (block == null) continue;
      if (localSource.hasMatch(line)) local = true;
      final m = kv.firstMatch(line);
      if (m != null) {
        if (inSource) {
          if (m.group(1) == 'type' &&
              (m.group(2) == 'directory' || m.group(2) == 'file')) {
            local = true;
          }
        } else if (!inSubTable) {
          // Les sous-tables (`[package.dependencies]`) ont des clés libres,
          // dont un éventuel paquet nommé « version ».
          block![m.group(1)!] = m.group(2)!;
        }
      }
      final s = sdistFile.firstMatch(line);
      if (s != null) sdistHash = s.group(1)!;
    }
    flush();
    return packages;
  }
}
