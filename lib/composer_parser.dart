import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart' show packageHash;
import 'models.dart';
import 'i18n.dart';

/// Parses `composer.lock` files (PHP) : sections `packages` et `packages-dev`.
class ComposerParser {
  List<WheelPackage> parseComposerLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('composer.lock introuvable : $path',
              'composer.lock not found: $path'));
      return [];
    }

    final Object? data;
    try {
      data = jsonDecode(file.readAsStringSync());
    } on FormatException catch (e) {
      stderr.writeln('Warning: ' +
          tr('analyse impossible de $path : $e', 'cannot parse $path: $e'));
      return [];
    }
    if (data is! Map) return [];

    final packages = <WheelPackage>[];
    final seen = <String>{};
    for (final section in const ['packages', 'packages-dev']) {
      for (final p in (data[section] as List? ?? const [])) {
        if (p is! Map) continue;
        final name = (p['name'] as String?) ?? '';
        var version = (p['version'] as String?) ?? '';
        if (name.isEmpty || version.isEmpty) continue;
        // Composer préfixe souvent les tags par `v` (`v1.2.3`).
        if (RegExp(r'^v\d').hasMatch(version)) version = version.substring(1);
        if (!seen.add('$name@$version')) continue;

        final dist = p['dist'] as Map?;
        final source = p['source'] as Map?;
        final hash = packageHash('SHA-1', (dist?['shasum'] as String?) ?? '');
        final authors = p['authors'] as List? ?? const [];
        final license = (p['license'] as List? ?? const []).join(' OR ');
        packages.add(WheelPackage(
          name: name,
          version: version,
          license: license,
          url: (p['homepage'] as String?) ??
              (source?['url'] as String?) ??
              'https://packagist.org/packages/$name',
          summary: (p['description'] as String?) ?? '',
          vendor: authors.isNotEmpty && authors.first is Map
              ? ((authors.first as Map)['name'] as String?) ?? ''
              : '',
          arch: 'any',
          sourceRef: path,
          hashes: [if (hash != null) hash],
          requires: [],
          provides: [name],
          packageType: 'composer',
        ));
      }
    }
    return packages;
  }
}
