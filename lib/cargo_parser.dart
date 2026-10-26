import 'dart:io';
import 'hash_utils.dart' show packageHash;
import 'models.dart';
import 'i18n.dart';

/// Parses `Cargo.lock` files (Rust).
///
/// Seuls les crates venant d'une source externe (registre, git) sont retenus :
/// les membres du workspace et les dépendances `path` n'ont pas de `source`
/// et ne sont pas des composants tiers.
class CargoParser {
  List<WheelPackage> parseCargoLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('Cargo.lock introuvable : {path}', {'path': path}));
      return [];
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    Map<String, String>? block;

    void flush() {
      final b = block;
      block = null;
      if (b == null) return;
      final name = b['name'] ?? '';
      final version = b['version'] ?? '';
      final source = b['source'] ?? '';
      if (name.isEmpty || version.isEmpty || source.isEmpty) return;
      if (!seen.add('$name@$version')) return;
      final hash = packageHash('SHA-256', b['checksum'] ?? '');
      packages.add(WheelPackage(
        name: name,
        version: version,
        license: '',
        url: 'https://crates.io/crates/$name',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        hashes: [if (hash != null) hash],
        requires: [],
        provides: [name],
        packageType: 'cargo',
      ));
    }

    // Les valeurs scalaires du format TOML de Cargo sont toujours des chaînes
    // entre guillemets sur une seule ligne ; les tableaux (`dependencies`)
    // ne nous intéressent pas.
    final kv = RegExp(r'^(\w+)\s*=\s*"(.*)"\s*$');
    for (final raw in file.readAsLinesSync()) {
      final line = raw.trim();
      if (line == '[[package]]') {
        flush();
        block = {};
        continue;
      }
      if (line.startsWith('[') && line != '[[package]]') {
        flush();
        continue;
      }
      final m = kv.firstMatch(line);
      if (m != null && block != null) block![m.group(1)!] = m.group(2)!;
    }
    flush();
    return packages;
  }
}
