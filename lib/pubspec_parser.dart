import 'dart:convert';
import 'dart:io';
import 'archive_helpers.dart' show identifyArchiveLicense;
import 'hash_utils.dart' show packageHash;
import 'models.dart';
import 'i18n.dart';

/// Version du SDK Flutter installé, sans lancer `flutter` : lue dans
/// `<racine>/bin/cache/flutter.version.json` (`frameworkVersion`) ou, pour les
/// anciennes installations, dans le fichier `<racine>/version`. La racine est
/// [flutterRoot], sinon `FLUTTER_ROOT`, sinon déduite de l'exécutable
/// `flutter` du `PATH`. `null` si introuvable.
///
/// Sans version réelle, le composant `flutter` d'un `pubspec.lock`
/// (`version: 0.0.0`) est émis sans version et les scanners lui attribuent
/// *toutes* les CVE du SDK, quelle que soit leur plage de versions affectées.
String? detectFlutterVersion(
    {String? flutterRoot,
    String? path,
    Map<String, String>? env,
    String? projectDir}) {
  final e = env ?? Platform.environment;
  // Projet épinglé avec FVM : sa version prime sur le Flutter global.
  if (projectDir != null) {
    final pinned = _fvmPinnedVersion(projectDir, e);
    if (pinned != null) return pinned;
  }
  final roots = <String>[
    if (flutterRoot != null && flutterRoot.isNotEmpty) flutterRoot,
    if ((e['FLUTTER_ROOT'] ?? '').isNotEmpty) e['FLUTTER_ROOT']!,
  ];
  for (final dir
      in (path ?? e['PATH'] ?? '').split(Platform.isWindows ? ';' : ':')) {
    if (dir.isEmpty) continue;
    final exe = File('$dir/flutter');
    if (exe.existsSync()) {
      try {
        roots.add(File(exe.resolveSymbolicLinksSync()).parent.parent.path);
      } catch (_) {}
    }
  }
  for (final root in roots) {
    try {
      final json = File('$root/bin/cache/flutter.version.json');
      if (json.existsSync()) {
        final v = (jsonDecode(json.readAsStringSync())
            as Map)['frameworkVersion'] as String?;
        if (v != null && v.trim().isNotEmpty) return v.trim();
      }
    } catch (_) {}
    try {
      final plain = File('$root/version');
      if (plain.existsSync()) {
        final v = plain.readAsLinesSync().firstOrNull?.trim();
        if (v != null && RegExp(r'^\d+\.\d+').hasMatch(v)) return v;
      }
    } catch (_) {}
  }
  return null;
}

final _versionRe = RegExp(r'^\d+\.\d+\.\d+');

/// Version de Flutter épinglée par FVM pour le projet de [dir] (ou l'un de ses
/// parents, jusqu'à 4 niveaux) : `.fvm/flutter_sdk` (lien vers le SDK, dont on
/// lit la version), `.fvmrc` (`{"flutter": "3.41.2"}`) ou l'ancien
/// `.fvm/fvm_config.json` (`flutterSdkVersion`). Un canal (`stable`, `beta`…)
/// n'est pas une version : on lit alors le SDK du cache FVM s'il existe.
String? _fvmPinnedVersion(String dir, Map<String, String> env) {
  var d = Directory(dir).absolute;
  for (var i = 0; i < 4; i++) {
    try {
      final link = Link('${d.path}/.fvm/flutter_sdk');
      if (link.existsSync() ||
          Directory('${d.path}/.fvm/flutter_sdk').existsSync()) {
        final root = link.existsSync()
            ? link.resolveSymbolicLinksSync()
            : '${d.path}/.fvm/flutter_sdk';
        final v =
            detectFlutterVersion(flutterRoot: root, path: '', env: const {});
        if (v != null) return v;
      }
      String? pin;
      final rc = File('${d.path}/.fvmrc');
      if (rc.existsSync()) {
        pin = (jsonDecode(rc.readAsStringSync()) as Map)['flutter'] as String?;
      }
      final legacy = File('${d.path}/.fvm/fvm_config.json');
      if (pin == null && legacy.existsSync()) {
        pin = (jsonDecode(legacy.readAsStringSync())
            as Map)['flutterSdkVersion'] as String?;
      }
      if (pin != null) {
        pin = pin.trim();
        if (_versionRe.hasMatch(pin)) return pin.split('@').first;
        // Canal : version du SDK dans le cache FVM.
        final cache = env['FVM_CACHE_PATH'] ??
            env['FVM_HOME'] ??
            (env['HOME'] != null ? '${env['HOME']}/fvm' : null);
        if (cache != null) {
          final v = detectFlutterVersion(
              flutterRoot: '$cache/versions/$pin', path: '', env: const {});
          if (v != null) return v;
        }
      }
    } catch (_) {}
    final parent = d.parent;
    if (parent.path == d.path) break;
    d = parent;
  }
  return null;
}

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
/// `git`, `path`, and `sdk` (`flutter`, `sky_engine`, `flutter_web_plugins`…).
///
/// `source: sdk` packages carry `version: "0.0.0"` in every lockfile (pub has
/// no real version for SDK-bundled packages). That placeholder is dropped —
/// the component is emitted without a version — unless the caller supplies the
/// real SDK version via [sdkVersions] (`{'flutter': '3.47.2'}`), keyed by the
/// SDK named in the lock entry's `description:` scalar.
///
/// A `pubspec.lock` carries no license data. When [pubCache] (the pub package
/// cache, usually `~/.pub-cache`) and/or [flutterRoot] are supplied,
/// [parsePubspecLock] reads the `LICENSE` file of each resolved package from
/// disk and identifies it via [identifyArchiveLicense].
class PubspecParser {
  static const _licenseFileNames = [
    'LICENSE',
    'LICENSE.md',
    'LICENSE.txt',
    'LICENCE',
    'COPYING',
    'license',
  ];

  /// Parses a `pubspec.lock` file. Produces one [WheelPackage] per package
  /// with `packageType='pub'` (PURL `pkg:pub/<name>@<version>`).
  List<WheelPackage> parsePubspecLock(String path,
      {Map<String, String> sdkVersions = const {},
      String? pubCache,
      String? flutterRoot}) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('pubspec.lock introuvable : $path',
              'pubspec.lock not found: $path'));
      return [];
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    var inPackages = false;

    String? key,
        dependency,
        source,
        version,
        sha256,
        descName,
        url,
        sdkName,
        resolvedRef,
        descPath;

    void flush() {
      if (key != null && dependency != 'direct dev') {
        // Pour `source: sdk`, `description:` est un scalaire qui nomme le SDK
        // (`flutter`, `dart`), pas le paquet — le nom du paquet est la clé.
        // `descName` (issu de `description.name`) ne concerne que `hosted`.
        final name = source == 'sdk'
            ? key!
            : ((descName != null && descName!.isNotEmpty) ? descName! : key!);
        // `pubspec.lock` écrit toujours "0.0.0" pour les paquets du SDK : on
        // n'émet pas cette fausse version, sauf si l'appelant a fourni la
        // version réelle du SDK (--sdk-version flutter=3.47.2).
        final ver = source == 'sdk'
            ? (sdkVersions[sdkName ?? ''] ?? '')
            : (version ?? '');
        if (name.isNotEmpty && seen.add('$name@$ver')) {
          final sha = sha256;
          final archiveHash = (sha != null && sha.isNotEmpty)
              ? packageHash('SHA-256', sha)
              : null;
          packages.add(WheelPackage(
            name: name,
            version: ver,
            license: _resolveLicense(
              lockPath: path,
              name: name,
              source: source,
              version: version,
              url: url,
              sdkName: sdkName,
              resolvedRef: resolvedRef,
              descPath: descPath,
              pubCache: pubCache,
              flutterRoot: flutterRoot,
            ),
            url: _homepage(name, source, url),
            summary: '',
            vendor: '',
            arch: 'any',
            sourceRef: path,
            hashes: [if (archiveHash != null) archiveHash],
            requires: [],
            provides: [name],
            packageType: 'pub',
          ));
        }
      }
      key = dependency = source = version =
          sha256 = descName = url = sdkName = resolvedRef = descPath = null;
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
          // Scalar form (`description: flutter`) → names the SDK, not the
          // package. Used only to look up the SDK version in [sdkVersions].
          if (rest.isNotEmpty) sdkName = _unquote(rest);
        }
      } else if (indent == 6) {
        if (content.startsWith('name:')) {
          descName = _unquote(content.substring('name:'.length));
        } else if (content.startsWith('sha256:')) {
          sha256 = _unquote(content.substring('sha256:'.length));
        } else if (content.startsWith('url:')) {
          url = _unquote(content.substring('url:'.length));
        } else if (content.startsWith('resolved-ref:')) {
          resolvedRef = _unquote(content.substring('resolved-ref:'.length));
        } else if (content.startsWith('path:')) {
          descPath = _unquote(content.substring('path:'.length));
        }
      }
    }
    flush();
    return packages;
  }

  /// Locates and identifies the `LICENSE` file of a resolved package on disk.
  /// Returns an SPDX identifier or `''` when not found / not identifiable.
  String _resolveLicense({
    required String lockPath,
    required String name,
    String? source,
    String? version,
    String? url,
    String? sdkName,
    String? resolvedRef,
    String? descPath,
    String? pubCache,
    String? flutterRoot,
  }) {
    final dirs = <String>[];
    switch (source) {
      case 'hosted':
        if (pubCache != null && version != null && version.isNotEmpty) {
          final host = _hostDir(url);
          dirs.add('$pubCache/hosted/$host/$name-$version');
        }
      case 'git':
        if (pubCache != null && resolvedRef != null) {
          final sub = (descPath == null || descPath.isEmpty || descPath == '.')
              ? ''
              : '/$descPath';
          dirs.add('$pubCache/git/$name-$resolvedRef$sub');
        }
      case 'path':
        if (descPath != null && descPath.isNotEmpty) {
          final base = File(lockPath).parent.path;
          dirs.add(descPath.startsWith('/') ? descPath : '$base/$descPath');
        }
      case 'sdk':
        if (flutterRoot != null) {
          dirs.add('$flutterRoot/packages/$name');
          dirs.add('$flutterRoot/bin/cache/pkg/$name');
          dirs.add(flutterRoot); // LICENSE racine du SDK, en dernier recours
        }
    }
    for (final dir in dirs) {
      for (final fn in _licenseFileNames) {
        final f = File('$dir/$fn');
        if (!f.existsSync()) continue;
        try {
          final spdx = identifyArchiveLicense(f.readAsStringSync());
          if (spdx.isNotEmpty) return spdx;
        } catch (_) {}
      }
    }
    return '';
  }

  /// Nom de répertoire du cache pour un registre `hosted` : l'hôte de l'URL
  /// (`https://pub.dev` → `pub.dev`), `pub.dev` par défaut.
  String _hostDir(String? url) {
    if (url == null || url.isEmpty) return 'pub.dev';
    return url.replaceFirst(RegExp(r'^https?://'), '').replaceAll('/', '');
  }

  /// Parses the `dependencies:` section of a `pubspec.yaml` file. Version
  /// constraints are reduced to a single version when unambiguous (`^1.2.3`,
  /// `1.2.3`, `>=1.2.3`); ranges and `any` produce an empty version. An SDK
  /// dependency (`flutter:\n    sdk: flutter`) takes its version from
  /// [sdkVersions] if supplied, otherwise none.
  List<WheelPackage> parsePubspecYaml(String path,
      {Map<String, String> sdkVersions = const {}}) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('pubspec.yaml introuvable : $path',
              'pubspec.yaml not found: $path'));
      return [];
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    var inDeps = false;

    String? pendingName;
    String pendingVersion = '';
    String? pendingSdk;

    void flush() {
      if (pendingName == null || !seen.add(pendingName!)) {
        pendingName = null;
        pendingVersion = '';
        pendingSdk = null;
        return;
      }
      final ver = pendingSdk != null
          ? (sdkVersions[pendingSdk!] ?? '')
          : pendingVersion;
      packages.add(WheelPackage(
        name: pendingName!,
        version: ver,
        license: '',
        url: 'https://pub.dev/packages/${pendingName!}',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        requires: [],
        provides: [pendingName!],
        packageType: 'pub',
      ));
      pendingName = null;
      pendingVersion = '';
      pendingSdk = null;
    }

    for (final raw in file.readAsLinesSync()) {
      final line = raw.trimRight();
      if (line.isEmpty || line.trimLeft().startsWith('#')) continue;

      if (!line.startsWith(' ')) {
        flush();
        inDeps = line == 'dependencies:';
        continue;
      }
      if (!inDeps) continue;

      final indent = line.length - line.trimLeft().length;
      var content = line.trim();
      final hashIdx = content.indexOf(' #');
      if (hashIdx >= 0) content = content.substring(0, hashIdx).trim();

      if (indent == 2) {
        flush();
        final colon = content.indexOf(':');
        if (colon < 0) continue;
        pendingName = _unquote(content.substring(0, colon));
        pendingVersion =
            _constraintToVersion(content.substring(colon + 1).trim());
      } else if (pendingName != null && content.startsWith('sdk:')) {
        // nested `sdk: flutter` under a dependency → SDK-sourced
        pendingSdk = _unquote(content.substring('sdk:'.length));
      }
    }
    flush();
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
