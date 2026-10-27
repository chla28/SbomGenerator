import 'dart:convert';
import 'dart:io';
import 'models.dart';
import 'i18n.dart';

/// Parses `Package.resolved` (Swift Package Manager, formats v1, v2 et v3).
class SwiftParser {
  List<WheelPackage> parsePackageResolved(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('Package.resolved introuvable : {path}', {'path': path}));
      return [];
    }
    final Object? data;
    try {
      data = jsonDecode(file.readAsStringSync());
    } on FormatException catch (e) {
      stderr.writeln('Warning: ' +
          tr('analyse impossible de {path} : {e}', {'path': path, 'e': e}));
      return [];
    }
    if (data is! Map) return [];

    // v1 : { object: { pins: [{ package, repositoryURL, state }] } }
    // v2/v3 : { pins: [{ identity, location, state }] }
    final pins = (data['pins'] ?? (data['object'] as Map?)?['pins']) as List?;
    final packages = <WheelPackage>[];
    final seen = <String>{};
    for (final pin in pins ?? const []) {
      if (pin is! Map) continue;
      final location =
          ((pin['location'] ?? pin['repositoryURL']) as String?) ?? '';
      final state = pin['state'] as Map? ?? const {};
      // Une dépendance épinglée sur une branche n'a pas de version : le
      // commit est alors la seule référence stable (purl-spec : tag ou commit).
      final version =
          ((state['version'] ?? state['revision']) as String?) ?? '';
      final id = _purlName(location);
      if (id.isEmpty || version.isEmpty) continue;
      if (!seen.add('$id@$version')) continue;
      final name = ((pin['identity'] ?? pin['package']) as String?) ?? id;
      packages.add(WheelPackage(
        name: id,
        version: version,
        license: '',
        url: location,
        summary: name,
        vendor: '',
        arch: 'any',
        sourceRef: path,
        requires: [],
        provides: [id],
        packageType: 'swift',
      ));
    }
    return packages;
  }

  /// `https://github.com/apple/swift-nio.git` → `github.com/apple/swift-nio`.
  String _purlName(String location) {
    var s = location.trim();
    s = s.replaceFirst(RegExp(r'^[a-z+]+://'), '');
    s = s.replaceFirst(RegExp(r'^[^@/]+@'), ''); // git@host:org/repo
    s = s.replaceFirst(':', '/');
    s = s.replaceFirst(RegExp(r'\.git$'), '');
    return s;
  }
}
