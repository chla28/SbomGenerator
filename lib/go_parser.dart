import 'dart:io';
import 'models.dart';

/// Parses Go module files: `go.sum` and `go.mod`.
class GoParser {
  /// Parses a `go.sum` file.
  ///
  /// Lines with `/go.mod` suffix are go.mod checksums (not the module source);
  /// they are skipped to avoid duplicate entries.
  List<WheelPackage> parseGoSum(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: go.sum file not found: $path');
      return [];
    }

    final seen = <String>{};
    final packages = <WheelPackage>[];

    for (final raw in file.readAsLinesSync()) {
      final line = raw.trim();
      if (line.isEmpty || line.startsWith('//')) continue;

      final parts = line.split(' ');
      if (parts.length < 2) continue;

      final module = parts[0];
      var version = parts[1];

      if (version.endsWith('/go.mod')) continue;
      if (version.startsWith('v')) version = version.substring(1);

      if (!seen.add('$module@$version')) continue;

      packages.add(WheelPackage(
        name: module,
        version: version,
        license: '',
        url: 'https://pkg.go.dev/$module',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        requires: [],
        provides: [module],
        packageType: 'golang',
      ));
    }
    return packages;
  }

  /// Parses a `go.mod` file and extracts `require` directives.
  ///
  /// Both block-form `require ( ... )` and single-line `require module version`
  /// are supported. `replace` and `exclude` directives are ignored.
  List<WheelPackage> parseGoMod(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: go.mod file not found: $path');
      return [];
    }

    final packages = <WheelPackage>[];
    bool inRequireBlock = false;

    for (final raw in file.readAsLinesSync()) {
      var line = raw.trim();

      final commentIdx = line.indexOf('//');
      if (commentIdx >= 0) line = line.substring(0, commentIdx).trim();
      if (line.isEmpty) continue;

      if (line == 'require (') {
        inRequireBlock = true;
        continue;
      }
      if (line == ')' && inRequireBlock) {
        inRequireBlock = false;
        continue;
      }
      // Start of any other block ends a require block
      if (!inRequireBlock && line.endsWith('(') && !line.startsWith('require')) {
        continue;
      }
      if (inRequireBlock && line == ')') {
        inRequireBlock = false;
        continue;
      }

      String? module, version;

      if (inRequireBlock) {
        final parts = line.split(RegExp(r'\s+'));
        if (parts.length >= 2) {
          module = parts[0];
          version = parts[1];
        }
      } else if (line.startsWith('require ') && !line.endsWith('(')) {
        final rest = line.substring('require '.length).trim();
        final parts = rest.split(RegExp(r'\s+'));
        if (parts.length >= 2) {
          module = parts[0];
          version = parts[1];
        }
      }

      if (module == null || version == null || module.isEmpty) continue;
      if (version.startsWith('v')) version = version.substring(1);

      packages.add(WheelPackage(
        name: module,
        version: version,
        license: '',
        url: 'https://pkg.go.dev/$module',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        requires: [],
        provides: [module],
        packageType: 'golang',
      ));
    }
    return packages;
  }
}
