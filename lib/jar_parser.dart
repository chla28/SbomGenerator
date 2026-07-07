import 'dart:io';
import 'models.dart';

/// Parses standalone Java `.jar` files to recover Maven coordinates.
///
/// Fallback chain (each step only runs if the previous one found nothing):
///   1. `META-INF/maven/*/*/pom.properties` — groupId/artifactId/version,
///      exactly as reported by the Maven build itself. Shaded/uber jars can
///      embed *several* `pom.properties` (their own plus relocated
///      dependencies) — only one whose artifactId matches the jar's own
///      filename is trusted; an ambiguous match is treated as "not found"
///      rather than risking picking up a bundled dependency's identity.
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
    final basename = path.split('/').last.replaceAll(RegExp(r'\.jar$'), '');
    final match = _versionSep.firstMatch(basename);
    final prefix = match != null ? basename.substring(0, match.start) : null;

    final pomCoords = await _fromPomProperties(path, expectedArtifactId: prefix);
    if (pomCoords != null) {
      final (groupId, artifactId, version) = pomCoords;
      return _toPackage(path, groupId, artifactId, version);
    }

    if (match == null || prefix == null) {
      stderr.writeln(
          'Warning: impossible de déterminer les coordonnées Maven de "$path" '
          '(pas de META-INF/maven/*/*/pom.properties exploitable, et aucun '
          'suffixe de version reconnaissable dans le nom de fichier)');
      return null;
    }
    final filenameVersion = basename.substring(match.start + 1);

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

    return _toPackage(path, groupId, artifactId, filenameVersion);
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

  /// [expectedArtifactId], when known, is the artifactId guessed from the
  /// jar's own filename (version suffix stripped). It disambiguates
  /// shaded/uber jars that embed more than one `pom.properties`.
  Future<(String, String, String)?> _fromPomProperties(
    String path, {
    required String? expectedArtifactId,
  }) async {
    // 1) Tentative ciblée : seul le pom.properties dont le segment artifactId
    // correspond au nom de fichier du jar est lu — évite de piocher les
    // métadonnées d'une dépendance relocalisée à l'intérieur d'un uber-jar
    // (ex. netty-common-*.jar qui embarque aussi le pom.properties de
    // jctools-core).
    if (expectedArtifactId != null) {
      final targeted = await _readPomProperties(
          path, 'META-INF/maven/*/$expectedArtifactId/pom.properties');
      if (targeted != null) return targeted;
    }

    // 2) Repli sur un glob large, mais uniquement si un unique pom.properties
    // matche : s'il y en a plusieurs, impossible de savoir lequel décrit le
    // jar lui-même plutôt qu'une dépendance embarquée — mieux vaut ne rien
    // affirmer que d'afficher une identité erronée.
    return _readPomProperties(
        path, 'META-INF/maven/*/*/pom.properties', requireSingleMatch: true);
  }

  Future<(String, String, String)?> _readPomProperties(
    String path,
    String globPattern, {
    bool requireSingleMatch = false,
  }) async {
    final ProcessResult result;
    try {
      result = await Process.run('unzip', ['-p', path, globPattern]);
    } on ProcessException {
      return null;
    }
    if (result.exitCode != 0) return null;

    final content = result.stdout.toString();
    if (content.trim().isEmpty) return null;

    if (requireSingleMatch && 'artifactId='.allMatches(content).length > 1) {
      return null;
    }

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
