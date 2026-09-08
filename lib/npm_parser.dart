import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart' show packageHashFromSri;
import 'models.dart';

/// Parses npm `package-lock.json` files (lockfileVersion 1, 2, and 3).
class NpmParser {
  List<WheelPackage> parsePackageLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: package-lock.json not found: $path');
      return [];
    }

    final Map<String, dynamic> root;
    try {
      root = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    } catch (e) {
      stderr.writeln('Warning: cannot parse $path: $e');
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
    final result = <WheelPackage>[];
    for (final entry in packages.entries) {
      if (entry.key.isEmpty) continue; // root project entry
      final data = entry.value as Map<String, dynamic>;
      final name = _stripNodeModulesPrefix(entry.key);
      final version = (data['version'] as String?) ?? '';
      result.add(_make(name, version, data, path));
    }
    return result;
  }

  List<WheelPackage> _parseDependenciesField(
      Map<String, dynamic> deps, String path) {
    final result = <WheelPackage>[];
    for (final entry in deps.entries) {
      final data = entry.value as Map<String, dynamic>;
      result.add(_make(entry.key, (data['version'] as String?) ?? '', data, path));
      final nested = data['dependencies'] as Map<String, dynamic>?;
      if (nested != null) result.addAll(_parseDependenciesField(nested, path));
    }
    return result;
  }

  WheelPackage _make(
      String name, String version, Map<String, dynamic> data, String path) {
    final license = _extractLicense(data);
    final resolved = (data['resolved'] as String?) ?? '';
    final integrity = packageHashFromSri(data['integrity'] as String?);
    return WheelPackage(
      name: name,
      version: version,
      license: license,
      url: resolved,
      summary: '',
      vendor: '',
      arch: 'any',
      sourceRef: path,
      hashes: [if (integrity != null) integrity],
      requires: [],
      provides: [name],
      packageType: 'npm',
    );
  }

  String _stripNodeModulesPrefix(String key) {
    const prefix = 'node_modules/';
    return key.startsWith(prefix) ? key.substring(prefix.length) : key;
  }

  String _extractLicense(Map<String, dynamic> data) {
    final lic = data['license'];
    if (lic is String) return lic;
    if (lic is List) return lic.whereType<String>().join(' OR ');
    return '';
  }
}
