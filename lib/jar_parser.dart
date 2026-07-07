import 'dart:io';
import 'models.dart';

/// Parses standalone Java `.jar` files to recover Maven coordinates.
///
/// Fallback chain (each step only runs if the previous one found nothing):
///   1. `META-INF/maven/*/*/pom.properties` — groupId/artifactId/version,
///      exactly as reported by the Maven build itself.
///   2. Filename convention `<groupId>.<artifactId>-<version>.jar`
///      (Quarkus/Red Hat style) — both coordinates come from the name.
///   3. Filename `<artifactId>-<version>.jar` (the vast majority of real
///      jars) + `META-INF/MANIFEST.MF` for a plausible groupId
///      (`Bundle-SymbolicName`, `Implementation-Vendor-Id`,
///      `Implementation-Title`, `Automatic-Module-Name`, in that priority
///      order — first one that looks like a real Java package name wins).
///   4. Filename only, artifactId reused as groupId, when nothing above
///      yields anything — this still produces a valid, non-dropped Maven
///      PURL (`pkg:maven/<artifactId>/<artifactId>@<version>`), matching
///      what tools such as syft do for jars with no embedded metadata.
///
/// Requires `unzip` in PATH. Returns `null` (with a stderr warning) only
/// when no version-like suffix can even be located in the filename.
class JarParser {
  static final _versionSep = RegExp(r'-(\d)');

  static const _manifestGroupIdKeys = [
    'Bundle-SymbolicName',
    'Implementation-Vendor-Id',
    'Implementation-Title',
    'Automatic-Module-Name',
  ];

  Future<WheelPackage?> parseJarFile(String path) async {
    final pomCoords = await _fromPomProperties(path);
    if (pomCoords != null) {
      final (groupId, artifactId, version) = pomCoords;
      return _toPackage(path, groupId, artifactId, version);
    }

    final basename = path.split('/').last.replaceAll(RegExp(r'\.jar$'), '');
    final match = _versionSep.firstMatch(basename);
    if (match == null) {
      stderr.writeln(
          'Warning: impossible de déterminer les coordonnées Maven de "$path" '
          '(pas de META-INF/maven/*/*/pom.properties, et aucun suffixe de '
          'version reconnaissable dans le nom de fichier)');
      return null;
    }
    final prefix = basename.substring(0, match.start);
    final version = basename.substring(match.start + 1);

    final lastDot = prefix.lastIndexOf('.');
    final String groupId;
    final String artifactId;
    if (lastDot > 0) {
      // Convention <groupId>.<artifactId>-<version>.jar (Quarkus/Red Hat).
      groupId = prefix.substring(0, lastDot);
      artifactId = prefix.substring(lastDot + 1);
    } else {
      artifactId = prefix;
      groupId = await _groupIdFromManifest(path) ?? prefix;
    }

    return _toPackage(path, groupId, artifactId, version);
  }

  WheelPackage _toPackage(
      String path, String groupId, String artifactId, String version) {
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

  /// Best-effort groupId from `META-INF/MANIFEST.MF`, for the common case of
  /// a jar with no embedded `pom.properties`. Only a value that looks like a
  /// genuine Java package name (dotted, lowercase) is accepted — manifest
  /// fields such as `Automatic-Module-Name` frequently hold non-package
  /// values (e.g. `javafx.baseEmpty`) that would otherwise produce a
  /// misleading groupId.
  Future<String?> _groupIdFromManifest(String path) async {
    final ProcessResult result;
    try {
      result =
          await Process.run('unzip', ['-p', path, 'META-INF/MANIFEST.MF']);
    } on ProcessException {
      return null;
    }
    if (result.exitCode != 0) return null;

    final content = result.stdout.toString();
    if (content.trim().isEmpty) return null;

    final values = <String, String>{};
    String? pendingKey;
    final buffer = StringBuffer();

    void flush() {
      if (pendingKey != null) {
        values.putIfAbsent(pendingKey!, () => buffer.toString().trim());
      }
      buffer.clear();
      pendingKey = null;
    }

    for (final rawLine in content.split('\n')) {
      final line = rawLine.replaceAll('\r', '');
      if (line.startsWith(' ')) {
        // Continuation line (RFC 822-style manifest line folding).
        buffer.write(line.substring(1));
        continue;
      }
      flush();
      final colon = line.indexOf(':');
      if (colon <= 0) continue;
      pendingKey = line.substring(0, colon).trim();
      buffer.write(line.substring(colon + 1).trim());
    }
    flush();

    for (final key in _manifestGroupIdKeys) {
      final value = values[key];
      if (value == null) continue;
      final candidate = value.split(';').first.trim();
      if (_looksLikeGroupId(candidate)) return candidate;
    }
    return null;
  }

  bool _looksLikeGroupId(String s) =>
      s.contains('.') && s == s.toLowerCase() && !s.contains(' ');
}
