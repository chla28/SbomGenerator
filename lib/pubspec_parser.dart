import 'dart:io';
import 'models.dart';

/// Parses Dart/Flutter dependency files: `pubspec.lock` and `pubspec.yaml`
/// (pure Dart, no `yaml` package dependency).
///
/// `pubspec.lock` yields resolved versions for the full transitive closure;
/// `pubspec.yaml` yields only the direct dependencies with their version
/// constraint (analogous to `go.sum` vs `go.mod`).
///
/// Dev dependencies are excluded:
///   * lock  — entries with `dependency: "direct dev"` are skipped;
///   * yaml  — the `dev_dependencies:` / `dependency_overrides:` sections are
///     skipped.
/// Transitive packages pulled in only by a dev dependency cannot be told
/// apart from production transitives in the lockfile, so they are kept.
///
/// All non-dev sources are reported: `hosted` (pub.dev or a custom registry),
/// `git`, `path`, and `sdk` (the `flutter` / `dart` pseudo-packages).
class PubspecParser {
  /// Parses a `pubspec.lock` file. Produces one [WheelPackage] per package
  /// with `packageType='pub'` (PURL `pkg:pub/<name>@<version>`).
  List<WheelPackage> parsePubspecLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: pubspec.lock not found: $path');
      return [];
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    var inPackages = false;

    String? key, dependency, source, version, sha256, descName, url;

    void flush() {
      if (key != null && dependency != 'direct dev') {
        final name = (descName != null && descName!.isNotEmpty) ? descName! : key!;
        final ver = version ?? '';
        if (name.isNotEmpty && seen.add('$name@$ver')) {
          packages.add(WheelPackage(
            name: name,
            version: ver,
            license: '',
            url: _homepage(name, source, url),
            summary: '',
            vendor: '',
            arch: 'any',
            sourceRef: path,
            sha256Header: sha256 ?? '',
            requires: [],
            provides: [name],
            packageType: 'pub',
          ));
        }
      }
      key = dependency = source = version = sha256 = descName = url = null;
    }

    for (final raw in file.readAsLinesSync()) {
      final line = raw.trimRight();
      if (line.isEmpty || line.trimLeft().startsWith('#')) continue;

      if (!line.startsWith(' ')) {
        flush();
        inPackages = line == 'packages:';
        continue;
      }
      if (!inPackages) continue;

      final indent = line.length - line.trimLeft().length;
      final content = line.trim();

      if (indent == 2 && content.endsWith(':')) {
        flush();
        key = _unquote(content.substring(0, content.length - 1));
        continue;
      }
      if (key == null) continue;

      if (indent == 4) {
        if (content.startsWith('dependency:')) {
          dependency = _unquote(content.substring('dependency:'.length));
        } else if (content.startsWith('source:')) {
          source = _unquote(content.substring('source:'.length));
        } else if (content.startsWith('version:')) {
          version = _unquote(content.substring('version:'.length));
        } else if (content.startsWith('description:')) {
          final rest = content.substring('description:'.length).trim();
          if (rest.isNotEmpty) descName = _unquote(rest); // scalar form (sdk)
        }
      } else if (indent == 6) {
        if (content.startsWith('name:')) {
          descName = _unquote(content.substring('name:'.length));
        } else if (content.startsWith('sha256:')) {
          sha256 = _unquote(content.substring('sha256:'.length));
        } else if (content.startsWith('url:')) {
          url = _unquote(content.substring('url:'.length));
        }
      }
    }
    flush();
    return packages;
  }

  /// Parses the `dependencies:` section of a `pubspec.yaml` file. Version
  /// constraints are reduced to a single version when unambiguous (`^1.2.3`,
  /// `1.2.3`, `>=1.2.3`); ranges and `any` produce an empty version.
  List<WheelPackage> parsePubspecYaml(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: pubspec.yaml not found: $path');
      return [];
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    var inDeps = false;

    for (final raw in file.readAsLinesSync()) {
      final line = raw.trimRight();
      if (line.isEmpty || line.trimLeft().startsWith('#')) continue;

      if (!line.startsWith(' ')) {
        inDeps = line == 'dependencies:';
        continue;
      }
      if (!inDeps) continue;

      final indent = line.length - line.trimLeft().length;
      if (indent != 2) continue; // nested git:/sdk:/path: detail lines

      var content = line.trim();
      final hashIdx = content.indexOf(' #');
      if (hashIdx >= 0) content = content.substring(0, hashIdx).trim();

      final colon = content.indexOf(':');
      if (colon < 0) continue;

      final name = _unquote(content.substring(0, colon));
      if (name.isEmpty || !seen.add(name)) continue;

      final rest = content.substring(colon + 1).trim();
      packages.add(WheelPackage(
        name: name,
        version: rest.isEmpty ? '' : _constraintToVersion(rest),
        license: '',
        url: 'https://pub.dev/packages/$name',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        requires: [],
        provides: [name],
        packageType: 'pub',
      ));
    }
    return packages;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  String _homepage(String name, String? source, String? url) {
    if (source == 'hosted') {
      if (url == null ||
          url.isEmpty ||
          url == 'https://pub.dev' ||
          url == 'https://pub.dartlang.org') {
        return 'https://pub.dev/packages/$name';
      }
      return '$url/packages/$name';
    }
    if (source == 'git') return url ?? '';
    return '';
  }

  String _constraintToVersion(String raw) {
    var t = _unquote(raw);
    if (t.isEmpty || t == 'any' || t.contains(' ')) return '';
    if (t.startsWith('^') || t.startsWith('~')) t = t.substring(1);
    final m = RegExp(r'^[<>=]*\s*([0-9][0-9A-Za-z.\-+]*)$').firstMatch(t);
    return m?.group(1) ?? '';
  }

  String _unquote(String s) {
    final t = s.trim();
    if (t.length >= 2 &&
        ((t.startsWith('"') && t.endsWith('"')) ||
            (t.startsWith("'") && t.endsWith("'")))) {
      return t.substring(1, t.length - 1);
    }
    return t;
  }
}
