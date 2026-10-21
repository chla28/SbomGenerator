import 'dart:io';
import 'hash_utils.dart' show packageHashFromSri;
import 'models.dart';
import 'i18n.dart';

/// Parses `pnpm-lock.yaml` files (formats v5, v6 and v9).
///
/// Lecture ligne à ligne de la section `packages:` : les clés diffèrent selon
/// la version du lockfile (`/nom/1.2.3` en v5, `/nom@1.2.3` en v6, `nom@1.2.3`
/// en v9) et peuvent porter un suffixe de pairs (`(react@18)` ou `_react@18`).
class PnpmParser {
  List<WheelPackage> parsePnpmLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('pnpm-lock.yaml introuvable : $path',
              'pnpm-lock.yaml not found: $path'));
      return [];
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    var inPackages = false;
    String? name;
    String? version;
    String? integrity;
    String? tarball;

    void flush() {
      final n = name, v = version;
      final hash = packageHashFromSri(integrity);
      if (n != null && v != null && seen.add('$n@$v')) {
        packages.add(WheelPackage(
          name: n,
          version: v,
          license: '',
          url: tarball ?? 'https://www.npmjs.com/package/$n',
          summary: '',
          vendor: '',
          arch: 'any',
          sourceRef: path,
          hashes: [if (hash != null) hash],
          requires: [],
          provides: [n],
          packageType: 'npm',
        ));
      }
      name = version = integrity = tarball = null;
    }

    final entry = RegExp(r'''^  ['"]?([^'"\s][^'"]*?)['"]?:\s*$''');
    for (final raw in file.readAsLinesSync()) {
      final line = raw.trimRight();
      if (line.isEmpty || line.trimLeft().startsWith('#')) continue;

      if (!line.startsWith(' ')) {
        flush();
        inPackages = line == 'packages:';
        continue;
      }
      if (!inPackages) continue;

      final m = entry.firstMatch(line);
      if (m != null) {
        flush();
        final parsed = _splitKey(m.group(1)!);
        name = parsed?.$1;
        version = parsed?.$2;
        continue;
      }
      if (name == null) continue;
      final trimmed = line.trim();
      if (trimmed.startsWith('resolution:')) {
        integrity = _flowValue(trimmed, 'integrity');
        tarball = _flowValue(trimmed, 'tarball');
      }
    }
    flush();
    return packages;
  }

  /// Valeur de [key] dans un mapping de flux YAML (`{integrity: sha512-…}`).
  String? _flowValue(String line, String key) {
    final m = RegExp('$key:\\s*([^,}\\s]+)').firstMatch(line);
    return m?.group(1)?.replaceAll(RegExp('^[\'"]|[\'"]\$'), '');
  }

  /// (nom, version) d'une clé de la section `packages:`, ou null si ce n'est
  /// pas un paquet publié (dépôt git, tarball local…).
  (String, String)? _splitKey(String key) {
    var k = key.startsWith('/') ? key.substring(1) : key;
    final peer = k.indexOf('(');
    if (peer > 0) k = k.substring(0, peer);

    // v5 : `nom/1.2.3` ou `@scope/nom/1.2.3_react@18` — la version suit le
    // dernier '/' et commence par un chiffre (un '@' éventuel est un pair).
    final slash = k.lastIndexOf('/');
    final v5 = slash > 0 &&
        RegExp(r'^\d').hasMatch(k.substring(slash + 1)) &&
        k.substring(0, slash).lastIndexOf('@') <= 0;
    final at = v5 ? -1 : k.lastIndexOf('@');
    String name, version;
    if (at > 0) {
      name = k.substring(0, at);
      version = k.substring(at + 1);
    } else {
      if (slash <= 0) return null;
      name = k.substring(0, slash);
      version = k.substring(slash + 1);
    }
    final under = version.indexOf('_');
    if (under > 0) version = version.substring(0, under);
    if (name.isEmpty || !RegExp(r'^\d').hasMatch(version)) return null;
    return (name, version);
  }
}
