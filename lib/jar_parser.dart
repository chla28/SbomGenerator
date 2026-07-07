import 'dart:io';
import 'models.dart';

/// Parses standalone Java `.jar` files to recover Maven coordinates.
///
/// Returns one [WheelPackage] per Maven artifact found in the jar: normally
/// just the jar's own identity, but a "shaded"/uber-jar that embeds
/// relocated dependencies (each with their own `META-INF/maven/*/*/pom.properties`)
/// yields one additional package per embedded dependency — mirroring what
/// tools such as syft report for the same jar.
///
/// Fallback chain for the jar's *own* identity (each step only runs if the
/// previous one found nothing):
///   1. The `pom.properties` whose artifactId matches the jar's own
///      filename (version suffix stripped).
///   2. Filename convention `<groupId>.<artifactId>-<version>.jar`
///      (Quarkus/Red Hat style) — both coordinates come from the name.
///   3. Filename `<artifactId>-<version>.jar` (the vast majority of real
///      jars): first [_knownGroupIdOverrides] (a small curated list of
///      well-known libraries, e.g. Spring Framework, whose real groupId
///      can't be recovered from the jar itself), then
///      `META-INF/MANIFEST.MF` for a plausible groupId (`Bundle-SymbolicName`,
///      `Implementation-Vendor-Id`, `Implementation-Title`,
///      `Automatic-Module-Name`, in that priority order — first one that
///      looks like a real Java package name wins).
///   4. Filename only, artifactId reused as groupId, when nothing above
///      yields anything — this still produces a valid, non-dropped Maven
///      PURL (`pkg:maven/<artifactId>/<artifactId>@<version>`), matching
///      what tools such as syft do for jars with no embedded metadata.
///
/// Requires `unzip` in PATH. Returns an empty list (with a stderr warning)
/// only when no version-like suffix can even be located in the filename and
/// no embedded `pom.properties` could be read at all.
class JarParser {
  static final _versionSep = RegExp(r'-(\d)');

  static final _pomPropertiesEntry =
      RegExp(r'^META-INF/maven/([^/\s]+)/([^/\s]+)/pom\.properties$');

  static const _manifestGroupIdKeys = [
    'Bundle-SymbolicName',
    'Implementation-Vendor-Id',
    'Implementation-Title',
    'Automatic-Module-Name',
  ];

  /// Curated artifactId → real Maven groupId overrides, for well-known
  /// libraries whose true groupId is not recoverable from the jar itself
  /// (no `pom.properties`, and `META-INF/MANIFEST.MF` only exposes a
  /// misleading value — e.g. `Automatic-Module-Name: spring.core`, which
  /// passes [_looksLikeGroupId] but is a JPMS module name, not the real
  /// Maven groupId `org.springframework`).
  ///
  /// Checked *before* the manifest heuristic so it always wins over a
  /// misleading manifest value. This matters for vulnerability scanning:
  /// scanners match CVEs against the real Maven coordinates, so a wrong
  /// groupId (`pkg:maven/spring.core/spring-core`) silently hides real,
  /// unfixed CVEs (e.g. CVE-2025-41249, CVE-2024-38820, CVE-2025-22233 on
  /// `org.springframework:spring-core`) instead of just being cosmetically
  /// imprecise.
  ///
  /// Deliberately narrow in scope — this is not an attempt to replicate a
  /// full CPE/package dictionary like syft's, only to close this specific,
  /// security-relevant gap. Spring Data/Integration/Retry/Security are not
  /// listed here: their manifests already expose the real groupId via
  /// `Implementation-Vendor-Id`.
  static const _knownGroupIdOverrides = {
    'spring-aop': 'org.springframework',
    'spring-aspects': 'org.springframework',
    'spring-beans': 'org.springframework',
    'spring-context': 'org.springframework',
    'spring-context-indexer': 'org.springframework',
    'spring-context-support': 'org.springframework',
    'spring-core': 'org.springframework',
    'spring-expression': 'org.springframework',
    'spring-instrument': 'org.springframework',
    'spring-jcl': 'org.springframework',
    'spring-jdbc': 'org.springframework',
    'spring-jms': 'org.springframework',
    'spring-messaging': 'org.springframework',
    'spring-orm': 'org.springframework',
    'spring-oxm': 'org.springframework',
    'spring-r2dbc': 'org.springframework',
    'spring-test': 'org.springframework',
    'spring-tx': 'org.springframework',
    'spring-web': 'org.springframework',
    'spring-webflux': 'org.springframework',
    'spring-webmvc': 'org.springframework',
    'spring-websocket': 'org.springframework',
  };

  Future<List<WheelPackage>> parseJarFile(String path) async {
    final basename = path.split('/').last.replaceAll(RegExp(r'\.jar$'), '');
    final match = _versionSep.firstMatch(basename);
    final prefix = match != null ? basename.substring(0, match.start) : null;

    final pomEntries = await _readAllPomProperties(path);

    // Sépare l'entrée qui décrit le jar lui-même (artifactId == nom de
    // fichier, ou seule entrée présente) du reste : les autres sont des
    // dépendances relocalisées embarquées (jar « shaded »/uber-jar).
    (String, String, String)? ownFromPom;
    final embedded = <(String, String, String)>[];
    if (pomEntries.isNotEmpty) {
      final ownIndex = prefix != null
          ? pomEntries.indexWhere((e) => e.$2 == prefix)
          : (pomEntries.length == 1 ? 0 : -1);
      for (var i = 0; i < pomEntries.length; i++) {
        if (i == ownIndex) {
          ownFromPom = pomEntries[i];
        } else {
          embedded.add(pomEntries[i]);
        }
      }
    }

    WheelPackage? ownPackage;
    if (ownFromPom != null) {
      final (groupId, artifactId, version) = ownFromPom;
      ownPackage = _toPackage(path, groupId, artifactId, version);
    } else if (prefix != null) {
      final version = basename.substring(match!.start + 1);
      final lastDot = prefix.lastIndexOf('.');
      final String groupId;
      final String artifactId;
      if (lastDot > 0) {
        // Convention <groupId>.<artifactId>-<version>.jar (Quarkus/Red Hat).
        groupId = prefix.substring(0, lastDot);
        artifactId = prefix.substring(lastDot + 1);
      } else {
        artifactId = prefix;
        groupId = _knownGroupIdOverrides[artifactId] ??
            await _groupIdFromManifest(path) ??
            prefix;
      }
      ownPackage = _toPackage(path, groupId, artifactId, version);
    }

    if (ownPackage == null && embedded.isEmpty) {
      stderr.writeln(
          'Warning: impossible de déterminer les coordonnées Maven de "$path" '
          '(pas de META-INF/maven/*/*/pom.properties exploitable, et aucun '
          'suffixe de version reconnaissable dans le nom de fichier)');
      return const [];
    }

    return [
      if (ownPackage != null) ownPackage,
      for (final (groupId, artifactId, version) in embedded)
        _toPackage(path, groupId, artifactId, version),
    ];
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

  /// Lists every `META-INF/maven/<groupId>/<artifactId>/pom.properties`
  /// entry embedded in the jar and reads each one *individually* (never
  /// concatenated) so that a shaded/uber-jar bundling several relocated
  /// dependencies never has one artifact's fields clobber another's.
  Future<List<(String, String, String)>> _readAllPomProperties(
      String path) async {
    final ProcessResult listResult;
    try {
      listResult = await Process.run('unzip', ['-l', path]);
    } on ProcessException {
      return const [];
    }
    if (listResult.exitCode != 0) return const [];

    final entries = <String>[];
    for (final line in listResult.stdout.toString().split('\n')) {
      final trimmed = line.trim();
      final lastSpace = trimmed.lastIndexOf(RegExp(r'\s'));
      if (lastSpace < 0) continue;
      final entryPath = trimmed.substring(lastSpace + 1);
      if (_pomPropertiesEntry.hasMatch(entryPath)) entries.add(entryPath);
    }
    if (entries.isEmpty) return const [];

    final results = <(String, String, String)>[];
    for (final entry in entries) {
      final coords = await _readSinglePomProperties(path, entry);
      if (coords != null) results.add(coords);
    }
    return results;
  }

  Future<(String, String, String)?> _readSinglePomProperties(
      String path, String entryPath) async {
    final ProcessResult result;
    try {
      result = await Process.run('unzip', ['-p', path, entryPath]);
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
