import 'dart:io';
import 'models.dart';
import 'i18n.dart';

/// Parses Python `requirements.txt` files (PEP 508 subset).
///
/// Each non-comment, non-directive line is turned into a minimal [WheelPackage]
/// with `packageType='pypi'`. Metadata fields other than name and version are
/// empty because requirements files contain no download-time metadata.
///
/// Supports:
///   • Pinned version: `requests==2.28.0` → version `2.28.0`
///   • Constrained: `requests>=2.0,<3.0` → version from first constraint
///   • Extras: `requests[security]==2.28.0` → extras stripped from name
///   • Bare name: `requests` → version empty
///
/// Skips: blank lines, comments (`#`), editable installs (`-e`), index
/// options (`-i`, `-f`, `-c`), and recursive includes (`-r`).
class RequirementsParser {
  static final _versionRe = RegExp(r'[=!<>~^]=?\s*[\w.*]+');
  static final _extrasRe = RegExp(r'\[.*?\]');
  static final _markerRe = RegExp(r'\s*;.*$');

  List<WheelPackage> parseFile(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('fichier requirements introuvable : $path',
              'requirements file not found: $path'));
      return [];
    }

    final packages = <WheelPackage>[];
    for (final raw in file.readAsLinesSync()) {
      final pkg = _parseLine(raw, path);
      if (pkg != null) packages.add(pkg);
    }
    return packages;
  }

  WheelPackage? _parseLine(String raw, String sourceRef) {
    var line = raw.trim();

    // Remove inline comment
    final hashIdx = line.indexOf(' #');
    if (hashIdx >= 0) line = line.substring(0, hashIdx).trim();

    if (line.isEmpty || line.startsWith('#')) return null;

    // Skip pip options / directives
    if (RegExp(r'^-[rRcCeEiIfF]').hasMatch(line)) return null;

    // Remove environment markers ("; python_version >= '3'")
    line = line.replaceAll(_markerRe, '').trim();

    // Extract version constraints before stripping extras
    final constraintMatch = _versionRe.firstMatch(line);
    String version = '';
    if (constraintMatch != null) {
      final constraint = constraintMatch.group(0)!.trim();
      // Use the pinned version if available, otherwise the first constraint
      if (constraint.startsWith('==')) {
        version = constraint.substring(2).trim();
      } else {
        final m = RegExp(r'[\d.*]+').firstMatch(constraint);
        version = m?.group(0) ?? '';
      }
    }

    // Strip extras and version spec to get the bare name
    var name = line
        .replaceAll(_extrasRe, '')
        .replaceAll(_versionRe, '')
        .replaceAll(RegExp(r'[=!<>~^,\s]+'), '')
        .trim();

    // Normalize per PEP 503
    name = name.toLowerCase().replaceAll(RegExp(r'[-_.]+'), '-');

    if (name.isEmpty) return null;

    return WheelPackage(
      name: name,
      version: version,
      license: '',
      url: '',
      summary: '',
      vendor: '',
      arch: 'any',
      sourceRef: sourceRef,
      requires: [],
      provides: [name],
      packageType: 'pypi',
    );
  }
}
