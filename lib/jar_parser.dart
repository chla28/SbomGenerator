import 'dart:io';
import 'models.dart';

/// Parses standalone Java `.jar` files to recover Maven coordinates.
///
/// Mirrors the fallback chain already used for OCI image scanning in
/// `oci_parser.dart`'s `_parseMavenJars`:
///   1. Read the embedded `META-INF/maven/*/*/pom.properties` (groupId,
///      artifactId, version) via `unzip -p`.
///   2. Otherwise, derive coordinates from the `<groupId>.<artifactId>-<version>.jar`
///      filename convention (Quarkus/Red Hat style).
///
/// Requires `unzip` in PATH. Returns `null` (with a stderr warning) when
/// neither source yields usable coordinates.
class JarParser {
  static final _versionSep = RegExp(r'-(\d)');

  Future<WheelPackage?> parseJarFile(String path) async {
    final coords = await _fromPomProperties(path) ?? _fromFilename(path);
    if (coords == null) {
      stderr.writeln(
          'Warning: impossible de déterminer les coordonnées Maven de "$path" '
          '(pas de META-INF/maven/*/*/pom.properties et nom de fichier non '
          'conforme à <groupId>.<artifactId>-<version>.jar)');
      return null;
    }

    final (groupId, artifactId, version) = coords;
    final name = groupId.isNotEmpty ? '$groupId:$artifactId' : artifactId;

    return WheelPackage(
      name: name,
      version: version,
      license: '',
      url: groupId.isNotEmpty
          ? 'https://mvnrepository.com/artifact/$groupId/$artifactId'
          : '',
      summary: '',
      vendor: groupId,
      arch: 'any',
      sourceRef: path,
      requires: const [],
      provides: [name],
      packageType: 'maven',
    );
  }

  Future<(String, String, String)?> _fromPomProperties(String path) async {
    final ProcessResult result;
    try {
      result = await Process.run(
          'unzip', ['-p', path, 'META-INF/maven/*/*/pom.properties']);
    } on ProcessException {
      return null;
    }
    if (result.exitCode != 0) return null;

    final content = result.stdout.toString();
    if (content.trim().isEmpty) return null;

    String? groupId, artifactId, version;
    for (final rawLine in content.split('\n')) {
      final line = rawLine.trim();
      if (line.isEmpty || line.startsWith('#')) continue;
      final eq = line.indexOf('=');
      if (eq <= 0) continue;
      final key = line.substring(0, eq).trim();
      final value = line.substring(eq + 1).trim();
      switch (key) {
        case 'groupId':
          groupId = value;
        case 'artifactId':
          artifactId = value;
        case 'version':
          version = value;
      }
    }
    if (groupId == null || artifactId == null || version == null) return null;
    if (groupId.isEmpty || artifactId.isEmpty || version.isEmpty) return null;
    return (groupId, artifactId, version);
  }

  (String, String, String)? _fromFilename(String path) {
    final basename = path.split('/').last.replaceAll(RegExp(r'\.jar$'), '');
    final match = _versionSep.firstMatch(basename);
    if (match == null) return null;
    final prefix = basename.substring(0, match.start);
    final version = basename.substring(match.start + 1);
    final lastDot = prefix.lastIndexOf('.');
    if (lastDot <= 0) return null;
    final groupId = prefix.substring(0, lastDot);
    final artifactId = prefix.substring(lastDot + 1);
    return (groupId, artifactId, version);
  }
}
