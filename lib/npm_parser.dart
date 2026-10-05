import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart' show packageHashFromSri;
import 'models.dart';
import 'i18n.dart';

/// Parses npm `package-lock.json` files (lockfileVersion 1, 2, and 3).
class NpmParser {
  List<WheelPackage> parsePackageLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('package-lock.json introuvable : $path',
              'package-lock.json not found: $path'));
      return [];
    }

    final Map<String, dynamic> root;
    try {
      root = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    } catch (e) {
      stderr.writeln('Warning: ' +
          tr('analyse impossible de $path : $e', 'cannot parse $path: $e'));
      return [];
    }

    final lockVersion = (root['lockfileVersion'] as int?) ?? 1;
    if (lockVersion >= 2 && root.containsKey('packages')) {
      return _parsePackagesField(
          root['packages'] as Map<String, dynamic>, path);
    }
    return _parseDependenciesField(
        (root['dependencies'] as Map<String, dynamic>?) ?? {}, path);
  }

  List<WheelPackage> _parsePackagesField(
      Map<String, dynamic> packages, String path) {
    final nmRoot = File(path).parent.path;
    final result = <WheelPackage>[];
    for (final entry in packages.entries) {
      if (entry.key.isEmpty) continue; // root project entry
      final data = entry.value as Map<String, dynamic>;
      final name = _stripNodeModulesPrefix(entry.key);
      final version = (data['version'] as String?) ?? '';
      // `entry.key` est le chemin d'installation réel (`node_modules/…`) :
      // le `package.json` correspondant porte l'auteur (absent du lockfile).
      result.add(_make(name, version, data, path,
          vendor: _authorFromPackageJson('$nmRoot/${entry.key}')));
    }
    return result;
  }

  List<WheelPackage> _parseDependenciesField(
      Map<String, dynamic> deps, String path) {
    final result = <WheelPackage>[];
    for (final entry in deps.entries) {
      final data = entry.value as Map<String, dynamic>;
      result.add(
          _make(entry.key, (data['version'] as String?) ?? '', data, path));
      final nested = data['dependencies'] as Map<String, dynamic>?;
      if (nested != null) result.addAll(_parseDependenciesField(nested, path));
    }
    return result;
  }

  WheelPackage _make(
      String name, String version, Map<String, dynamic> data, String path,
      {String vendor = ''}) {
    final license = _extractLicense(data);
    final resolved = (data['resolved'] as String?) ?? '';
    final integrity = packageHashFromSri(data['integrity'] as String?);
    return WheelPackage(
      name: name,
      version: version,
      license: license,
      url: resolved,
      summary: '',
      vendor: vendor,
      arch: 'any',
      sourceRef: path,
      hashes: [if (integrity != null) integrity],
      requires: [],
      provides: [name],
      packageType: 'npm',
    );
  }

  /// Lit le nom d'auteur/éditeur depuis `<dir>/package.json` (`author`,
  /// sinon premier `contributors[]`, sinon `maintainers[]`). Le lockfile npm
  /// ne contient pas cette information ; l'arbre `node_modules` peut être
  /// absent (lockfile committé sans `npm install`) → chaîne vide, sans erreur.
  String _authorFromPackageJson(String dir) {
    try {
      final f = File('$dir/package.json');
      if (!f.existsSync()) return '';
      final j = jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
      final fromAuthor = _personName(j['author']);
      if (fromAuthor.isNotEmpty) return fromAuthor;
      for (final key in const ['contributors', 'maintainers']) {
        final list = j[key];
        if (list is List) {
          for (final p in list) {
            final n = _personName(p);
            if (n.isNotEmpty) return n;
          }
        }
      }
      return '';
    } catch (_) {
      return '';
    }
  }

  /// Normalise un champ « person » npm : objet `{name,…}` ou chaîne
  /// `"Nom <email> (url)"` → `"Nom"`.
  String _personName(Object? person) {
    if (person is Map) return (person['name'] as String?)?.trim() ?? '';
    if (person is String) {
      final m = RegExp(r'^\s*([^<(]+?)\s*(?:[<(]|$)').firstMatch(person);
      return m != null ? m.group(1)!.trim() : person.trim();
    }
    return '';
  }

  String _stripNodeModulesPrefix(String key) {
    const prefix = 'node_modules/';
    final i = key.lastIndexOf(prefix);
    return i >= 0 ? key.substring(i + prefix.length) : key;
  }

  String _extractLicense(Map<String, dynamic> data) {
    final lic = data['license'];
    if (lic is String) return lic;
    if (lic is List) return lic.whereType<String>().join(' OR ');
    return '';
  }
}
